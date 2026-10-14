#!/usr/bin/env python3
"""S4 (F0) — delink mínimo: sintetiza objetos-alvo COFF x86-64 a partir do GameAssembly.dll.

- lê inventário (rva, end, name, sec, src)
- escreve um .obj COFF com: seção .text = bytes da função, símbolo global, relocs
  (E8/E9 rel32 e operandos [rip+disp]) apontando para símbolos por endereço
- o símbolo de seção e a string table são incluídos (nomes > 8 usam /offset)
"""
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

IMAGE_BASE = 0x180000000
AMD64_REL32 = 0x0004


def load_dll(path):
    d = Path(path).read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    opt = pe + 24
    secs = []
    for i in range(nsec):
        o = opt + optsz + i * 40
        nm = d[o:o + 8].rstrip(b"\0").decode()
        vs, va, rs, ra = struct.unpack_from("<IIII", d, o + 8)
        secs.append((nm, va, vs, ra, rs))
    return d, secs


def rva2off(secs, r):
    for n, va, vs, ra, rs in secs:
        if va <= r < va + max(vs, rs):
            return ra + (r - va)
    return None


def coff_symbol(name, value, section, stype, storage):
    if len(name) > 8:
        raise ValueError("use string table")
    return name.encode().ljust(8, b"\0") + struct.pack("<IhHBB", value, section, stype, storage, 0)


def write_coff(path, text, symbols, relocs):
    """symbols: [(name, value, section:int, type, storage)] ; relocs: [(offset, sym_index)]"""
    strtab = b"\0\0\0\0"
    symbytes = b""
    name2off = {}

    def sym(name, value, section, stype, storage):
        nonlocal symbytes, strtab
        if len(name) <= 8:
            nm = name.encode().ljust(8, b"\0")
        else:
            if name not in name2off:
                name2off[name] = len(strtab)
                strtab += name.encode() + b"\0"
            nm = struct.pack("<II", 0, name2off[name])
        symbytes += nm + struct.pack("<IhHBB", value, section, stype, storage, 0)
        return (len(symbytes) // 18) - 1

    # section symbol first
    sec_sym = sym(".text", 0, 1, 0, 3)
    idx = {}
    for name, value, section, stype, storage in symbols:
        idx[name] = sym(name, value, section, stype, storage)

    relbytes = b""
    for off, sname in relocs:
        relbytes += struct.pack("<IIH", off, idx[sname], AMD64_REL32)

    nsym = len(symbytes) // 18
    hdr_len = 20 + 40
    raw_off = hdr_len
    reloc_off = raw_off + len(text)
    sym_off = reloc_off + len(relbytes)
    out = struct.pack("<HHIIIHH", 0x8664, 1, 0, sym_off, nsym, 0, 0)
    out += b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0, 0, len(text), raw_off, reloc_off, 0, len(relocs), 0, 0x60500020)
    out += text + relbytes + symbytes + struct.pack("<I", len(strtab)) + strtab[4:]
    Path(path).write_bytes(out)


def synth_target(dll, secs, rva, end, name, out):
    off = rva2off(secs, rva)
    text = bytearray(dll[off:off + (end - rva)])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    calls = []  # (reloc_offset_in_section, target_rva)
    datarefs = []
    for ins in md.disasm(text, IMAGE_BASE + rva):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                tva = ins.address + ins.size + op.mem.disp
                reloc_at = (ins.address - (IMAGE_BASE + rva)) + ins.encoding.disp_offset
                datarefs.append((reloc_at, tva - IMAGE_BASE, ins.mnemonic))
        if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == 2 and ins.encoding.imm_size == 4:
            tva = ins.operands[0].imm
            reloc_at = (ins.address - (IMAGE_BASE + rva)) + ins.encoding.imm_offset
            calls.append((reloc_at, tva - IMAGE_BASE))
    syms = [(name, 0, 1, 0x20, 2)]
    rels = []
    reloc_ats = []
    for reloc_at, trva in calls:
        sname = f"sub_{trva:x}"
        if all(s[0] != sname for s in syms):
            syms.append((sname, 0, 0, 0x20, 2))  # undefined extern
        rels.append((reloc_at, sname))
        reloc_ats.append(reloc_at)
    # data refs: absolute symbols (section 0xFFFF = ABSOLUTE)
    for reloc_at, trva, _ in datarefs:
        sname = f"data_{trva:x}"
        if all(s[0] != sname for s in syms):
            syms.append((sname, IMAGE_BASE + trva, 0xFFFF, 0, 3))
        rels.append((reloc_at, sname))
        reloc_ats.append(reloc_at)
    for reloc_at in reloc_ats:  # como no .obj do compilador: o linker resolve o campo
        text[reloc_at:reloc_at + 4] = b"\0\0\0\0"
    write_coff(out, bytes(text), syms, rels)
    return {"size": len(text), "calls": calls, "datarefs": datarefs, "relocs": rels}


if __name__ == "__main__":
    import sys
    dll, secs = load_dll("/home/faga/Documents/apogea-rea/game-real/GameAssembly.dll")
    inv = json.loads(Path("/tmp/opencode/decomp-unity/inventory.json").read_text())
    by_rva = {x[0]: x for x in inv}
    for rva in [int(a, 16) for a in sys.argv[1:]]:
        x = by_rva.get(rva)
        if not x:
            print(f"0x{rva:x}: não está no inventário"); continue
        r, e, nm, sec, src = x
        out = f"/tmp/opencode/decomp-unity/s4/target_{rva:x}.obj"
        Path("/tmp/opencode/decomp-unity/s4").mkdir(exist_ok=True)
        symname = re.sub(r"[^0-9A-Za-z_]", "_", nm.replace("::", "_"))
        info = synth_target(dll, secs, r, e, symname, out)
        print(f"0x{rva:x} {nm} ({info['size']}b) calls={[(hex(o),hex(t)) for o,t in info['calls']]} "
              f"datarefs={[(hex(o),hex(t),m) for o,t,m in info['datarefs']]} -> {out}")
