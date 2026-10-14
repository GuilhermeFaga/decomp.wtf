#!/usr/bin/env python3
"""S2 (F0) — inventário unificado de funções do GameAssembly.dll do Apogea.

Fontes:
  - .pdata (PE x64): boundaries exatos de ~48k funções (todas)
  - dumps/decomp/methods_final.json: 91k métodos gerenciados (nome, mod, rva)
  - dumps/decomp/symbols.txt: 63k nomes (Mod::Metodo, endereço hex = RVA)

Saída: /tmp/opencode/decomp-unity/inventory.json  (lista [rva, end, name, sec, src])
Valida RVAs conhecidos de sessões anteriores (0x1a9e30 = Setup#3, 0x70e00 = Root::geWpgwW).
"""
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import argparse

ap = argparse.ArgumentParser()
ap.add_argument("--dll", default="/home/faga/Documents/apogea-rea/game-real/GameAssembly.dll")
ap.add_argument("--out", default="/tmp/opencode/decomp-unity/inventory.json")
args = ap.parse_args()
GAME = Path(args.dll)
REPO = Path("/home/faga/Documents/apogea-rea")
OUT = Path(args.out)

d = GAME.read_bytes()
print(f"dll: {GAME} ({len(d)} bytes)")
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = struct.unpack_from("<H", d, pe + 20)[0]
opt = pe + 24
imgbase = struct.unpack_from("<Q", d, opt + 24)[0]
secs = []
so = opt + optsz
for i in range(nsec):
    o = so + i * 40
    name = d[o:o + 8].rstrip(b"\0").decode()
    vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, o + 8)
    secs.append((name, vaddr, vsize, raddr, rsize))
ndd = struct.unpack_from("<I", d, opt + 108)[0]
dds = [struct.unpack_from("<II", d, opt + 112 + i * 8) for i in range(ndd)]


def rva2off(r):
    for n, va, vs, ra, rs in secs:
        if va <= r < va + max(vs, rs):
            return ra + (r - va)
    return None


def sec_of(r):
    for n, va, vs, ra, rs in secs:
        if va <= r < va + max(vs, rs):
            return n
    return "?"


def bytes_at(rva, n):
    o = rva2off(rva)
    return d[o:o + n] if o is not None else b""


# ---- .pdata ----
exc = dds[3]
off = rva2off(exc[0]); end = off + exc[1]
spans = []
while off + 12 <= end:
    b, e, uw = struct.unpack_from("<III", d, off)
    if b == 0 and e == 0:
        break
    spans.append((b, e))
    off += 12

# ---- nomes ----
methods = json.loads((REPO / "dumps/decomp/methods_final.json").read_text())
name_by_rva = {}
for m in methods:
    rva = m.get("rva")
    if not rva or rva in name_by_rva:
        continue
    name_by_rva[rva] = {"name": m["name"], "mod": m.get("mod", ""), "type": m.get("type", "")}
syms = {}
for line in (REPO / "dumps/decomp/symbols.txt").read_text().splitlines():
    if not line.strip():
        continue
    a, _, nm = line.partition("\t")
    try:
        syms[int(a, 16)] = nm
    except ValueError:
        pass

# ---- unificado ----
inv = []
starts = {b for b, e in spans}
sec_count = {}
covered = 0
for b, e in spans:
    s = sec_of(b)
    sec_count[s] = sec_count.get(s, 0) + 1
    covered += e - b
    nm = None
    src = "func"
    if b in syms:
        nm, src = syms[b], "sym"
    elif b in name_by_rva:
        nm, src = name_by_rva[b]["name"], "meta"
    inv.append([b, e, nm, s, src])
# métodos sem entrada em .pdata (leaf sem unwind?) — incluir como funções sem fim conhecido
nop = [r for r in name_by_rva if r not in starts]
for r in sorted(nop):
    inv.append([r, None, name_by_rva[r]["name"], sec_of(r), "meta-nopdata"])
inv.sort(key=lambda x: x[0])
OUT.write_text(json.dumps(inv))

md = Cs(CS_ARCH_X86, CS_MODE_64)
print(f"pdata spans: {len(spans)}  cobrindo {covered} bytes ({covered / (1024*1024):.1f} MiB)")
print(f"por seção: {sec_count}")
print(f"nomes: sym={sum(1 for x in inv if x[4]=='sym')} meta={sum(1 for x in inv if x[4]=='meta')} "
      f"sem nome={sum(1 for x in inv if x[4]=='func')} meta-sem-pdata={len(nop)}")
start_names = {x[0] for x in inv if x[4] in ("sym", "meta")}
print(f"starts com nome: {len(start_names)} | methods c/ rva: {len(name_by_rva)} | "
      f"methods com start em pdata: {len([r for r in name_by_rva if r in starts])}")

print("\n--- validação de funções conhecidas ---")
for rva, want in [(0x1a9e30, "Setup#3"), (0x70e00, "Root::geWpgwW")]:
    inp = rva in starts
    nm = syms.get(rva) or (name_by_rva.get(rva) or {}).get("name") or "-"
    code = bytes_at(rva, 24)
    ins = list(md.disasm(code, imgbase + rva))[:4]
    print(f"  0x{rva:x} ({want}): pdata-start={inp} nome={nm!r} sec={sec_of(rva)}")
    for i in ins:
        print(f"    0x{i.address:012x}  {i.mnemonic} {i.op_str}")
    # fim do span
    for b, e in spans:
        if b == rva:
            print(f"    span: 0x{b:x}..0x{e:x} ({e-b} bytes)")
            break
