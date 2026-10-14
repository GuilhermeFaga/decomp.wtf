"""Unity IL2CPP (Windows x64) decompilation projects, from the game's own GameAssembly.dll.

A Unity game built with IL2CPP ships two things worth having: `GameAssembly.dll`, the compiled program, and
`global-metadata.dat`, which names every managed method. This module turns them into an objdiff project the
fork engine can work on exactly like a community decomp:

- **inventory**: every function boundary comes from the PE's `.pdata` (x64 unwind tables: exact start and end,
  generated code and engine code alike). Names come from a symbol map when one is available (the game's own
  metadata, or a map a RE session produced: `symbols.txt` "address<TAB>name" and/or `methods_final.json`
  entries with `name`/`type`/`mod`/`rva`). Without one, every function is `func_<rva>`.
- **target objects**: one synthetic COFF per source file — the original bytes of its functions, their symbols,
  and the relocations the compiler would have written (calls, jumps, `[rip+disp]` data references) with the
  relocated field zeroed, the pre-link convention — so objdiff can resolve names on both sides.
- **units**: a source file per assembly chunk (managed code) or engine cluster: `src/<module>/<NNN>.cpp`, with
  `include/context.h` for shared types. Agents fill them in one function at a time.
- **build**: clang targeting x86-64 Windows (`--target=x86_64-pc-windows-msvc`) through ninja; every source
  file builds on its own and objdiff judges each function, like any fork's units.

Nothing from the game goes into the project's sources: target objects hold the original machine code (which the
game's owner already has) and `orig/` (the DLL and metadata) stays out of exports and git.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

MACHINE_X64 = 0x8664
MACHINE_X86 = 0x14C
DIR_EXCEPTION = 3
SYM_UNDEFINED = 0
SYM_ABSOLUTE = -1  # IMAGE_SYM_ABSOLUTE as the signed 16-bit COFF section number
STYPE_FUNCTION = 0x20
CLASS_EXTERNAL = 2
CLASS_STATIC = 3
REL32 = 0x0004
DATA_PREFIX = "data_"
FUNC_PREFIX = "func_"
DEFAULT_CHUNK = 128
DEFAULT_MAX_FUNCTIONS = 6000  # what an import generates up front; --all generates every function
# clang flags: MSVC ABI and a plain -O2, close to IL2CPP's /O2 (scores get calibrated further by comparison)
CLANG_FLAGS = ["--target=x86_64-pc-windows-msvc", "-O2", "-std=c++17", "-c", "-Iinclude"]
_BAD = re.compile(r"[^0-9A-Za-z_]")
LIBRARY = re.compile(r"^(System|mscorlib|Mono\.|Microsoft\.|Newtonsoft|Unity\.|UnityEngine|netstandard|nunit)")


class UnityError(RuntimeError):
    """Anything the user should read as is (a folder that isn't a Unity build, a tool that isn't there)."""


# ---------------------------------------------------------------------------- PE files


@dataclass
class Section:
    name: str
    vaddr: int
    vsize: int
    raw: int
    rsize: int


@dataclass
class Pe:
    """The little of a Windows PE file this needs: sections, image base and data directories."""

    data: bytes
    machine: int
    image_base: int
    sections: list[Section]
    dirs: list[tuple[int, int]]
    path: Path

    @classmethod
    def load(cls, path: Path) -> "Pe":
        data = Path(path).read_bytes()
        path = Path(path)
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise UnityError(f"{path.name} isn't a Windows program (PE file)")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise UnityError(f"{path.name} isn't a valid PE file")
        machine, nsec = struct.unpack_from("<HH", data, pe + 4)
        optsize = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        if optsize < 112:
            raise UnityError(f"{path.name} has no optional header")
        magic = struct.unpack_from("<H", data, opt)[0]
        image_base = (struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B
                      else struct.unpack_from("<I", data, opt + 28)[0])
        ndd = struct.unpack_from("<I", data, opt + 108)[0]
        dirs = [struct.unpack_from("<II", data, opt + 112 + i * 8) for i in range(min(ndd, 16))]
        sections = []
        for i in range(nsec):
            o = opt + optsize + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, o + 8)
            sections.append(Section(name, vaddr, vsize, raw, rsize))
        return cls(data, machine, image_base, sections, dirs, path)

    def off(self, rva: int) -> int | None:
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.rsize):
                return s.raw + (rva - s.vaddr)
        return None

    def section(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.rsize):
                return s
        return None

    def read(self, rva: int, size: int) -> bytes:
        o = self.off(rva)
        return self.data[o:o + size] if o is not None else b""

    @property
    def has_il2cpp_section(self) -> bool:
        return any(s.name == "il2cpp" for s in self.sections)


def read_pdata(pe: Pe) -> list[tuple[int, int]]:
    """(start, end) of every function in the PE's .pdata (x64 unwind info): exact, generated code included."""
    if len(pe.dirs) <= DIR_EXCEPTION or not pe.dirs[DIR_EXCEPTION][1]:
        return []
    base, size = pe.dirs[DIR_EXCEPTION]
    off = pe.off(base)
    if off is None:
        return []
    out = []
    for at in range(off, min(off + size, len(pe.data)) - 11, 12):
        beg, end, _ = struct.unpack_from("<III", pe.data, at)
        if beg == 0 and end == 0:
            break
        if beg < end:
            out.append((beg, end))
    return sorted(set(out))


# ---------------------------------------------------------------------------- function inventory


@dataclass
class Fn:
    rva: int
    end: int
    name: str          # canonical name ("Type::Method"), or func_<rva>
    flat: str          # the C identifier agents write and objects carry
    module: str        # assembly name, or the engine section
    section: str
    named: bool


def flat_symbol(name: str) -> str:
    """A C identifier for a managed name: Namespace::Type::Method -> Namespace_Type_Method."""
    out = _BAD.sub("_", name.replace("::", "_"))
    out = re.sub(r"_+", "_", out).strip("_")
    if not out or out[0].isdigit():
        out = "fn_" + out
    return out[:180]


def load_symbol_map(paths: list[Path]) -> tuple[dict[int, str], dict[int, str]]:
    """(names, modules) by RVA, from any symbols.txt ("address<TAB>name") and methods_final.json files.

    methods_final.json carries the managed assembly each method belongs to (`mod`), which groups units;
    symbols.txt carries the full names. Later files refine earlier ones."""
    names: dict[int, str] = {}
    mods: dict[int, str] = {}
    for p in paths:
        try:
            text = p.read_text(errors="replace", encoding="utf-8")
        except OSError:
            continue
        if p.name in ("symbols.txt", "symbols") or re.match(r"^[0-9a-fA-F]+\t", text[:64]):
            for line in text.splitlines():
                addr, _, name = line.partition("\t")
                if not name and " " in line:
                    addr, _, name = line.partition(" ")
                try:
                    rva = int(addr.strip(), 16)
                except ValueError:
                    continue
                name = name.strip()
                if name:
                    names[rva] = name
        elif p.suffix == ".json":
            try:
                rows = json.loads(text)
            except ValueError:
                continue
            if isinstance(rows, dict):
                rows = rows.get("methods") or rows.get("functions") or []
            for m in rows:
                if not isinstance(m, dict) or not m.get("rva"):
                    continue
                rva = int(m["rva"])
                typ, nm = m.get("type") or "", m.get("name") or ""
                full = f"{typ}::{nm}" if typ and nm else (nm or typ)
                if full and rva not in names:
                    names[rva] = full
                if m.get("mod"):
                    mods.setdefault(rva, m["mod"])
    return names, mods


def find_symbol_files(where: Path) -> list[Path]:
    """Symbol maps next to the game (or in dumps/decomp, where a RE session would leave them)."""
    hits: list[Path] = []
    for p in (where, where / "symbols", where / "decomp", where / "dumps" / "decomp"):
        for name in ("symbols.txt", "methods_final.json", "methods.json", "symbols.json"):
            f = p / name
            if f.is_file() and f not in hits:
                hits.append(f)
    return hits


def build_inventory(pe: Pe, names: dict[int, str], mods: dict[int, str]) -> list[Fn]:
    """Every function: .pdata gives exact boundaries, the symbol map names them, and metadata RVAs without
    unwind info (leaf functions) get what's left between two other functions."""
    import bisect

    spans = read_pdata(pe)
    span_end = {b: e for b, e in spans}
    span_starts = sorted(span_end)
    alias: dict[int, str] = {}
    leafs: set[int] = set()
    for rva in sorted(names):
        if rva in span_end:
            continue
        k = bisect.bisect_right(span_starts, rva) - 1
        if k >= 0 and rva < span_end[span_starts[k]]:
            alias.setdefault(span_starts[k], names[rva])  # generic sharing: another name for that function
        else:
            leafs.add(rva)
    starts = sorted(set(span_end) | leafs)
    out: list[Fn] = []
    for i, rva in enumerate(starts):
        sec = pe.section(rva)
        if sec is None:
            continue
        nxt = starts[i + 1] if i + 1 < len(starts) else sec.vaddr + sec.vsize
        end = min(span_end.get(rva, nxt), nxt)
        if end <= rva:
            continue
        name = names.get(rva) or alias.get(rva)
        module = mods.get(rva) or ("engine" if sec.name == ".text" else sec.name)
        out.append(Fn(rva, end, name or f"{FUNC_PREFIX}{rva:x}", "", module, sec.name, bool(name)))
    for fn in out:
        fn.flat = flat_symbol(fn.name)
    _dedupe_flats(out)
    return out


def _dedupe_flats(fns: list[Fn]) -> None:
    """Two different functions can sanitize to the same identifier: give later ones their address."""
    taken = {f.flat for f in fns}
    seen: set[str] = set()
    for fn in fns:
        if fn.flat in seen:
            base = f"{fn.flat}_{fn.rva:x}"
            while base in taken:
                base += "_"
            taken.add(base)
            fn.flat = base
        seen.add(fn.flat)


# ---------------------------------------------------------------------------- units


@dataclass
class Unit:
    name: str
    fns: list[Fn]
    module: str

    @property
    def source(self) -> str:
        return f"src/{self.name}.cpp"

    @property
    def target(self) -> str:
        return f"target/{self.name}.obj"

    @property
    def base(self) -> str:
        return f"build/{self.name}.obj"


def module_rank(module: str, section: str) -> int:
    """Game code first (Assembly-CSharp is Unity's game assembly), then other game assemblies, then engines."""
    if module in ("Assembly-CSharp.dll", "Assembly-CSharp"):
        return 0
    if module == "engine":
        return 3
    if module.endswith(".dll") or module.endswith(".exe"):
        return 2 if LIBRARY.match(module) else 1
    return 4 if section == "il2cpp" else 3


def plan_units(fns: list[Fn], chunk: int = DEFAULT_CHUNK,
               max_functions: int | None = DEFAULT_MAX_FUNCTIONS) -> list[Unit]:
    """Group functions into source files: by assembly for managed code, in address order, taking modules by
    priority until the function budget is spent (None/0: everything)."""
    by_module: dict[str, list[Fn]] = {}
    for fn in fns:
        by_module.setdefault(fn.module, []).append(fn)
    order = sorted(by_module, key=lambda m: (module_rank(m, by_module[m][0].section), m))
    units: list[Unit] = []
    left = max_functions if max_functions else None
    for module in order:
        group = sorted(by_module[module], key=lambda f: f.rva)
        stem = re.sub(r"[^0-9A-Za-z_.+-]", "_", re.sub(r"\.(dll|exe)$", "", module)) or "engine"
        for i in range(0, len(group), chunk):
            piece = group[i:i + chunk]
            if left is not None:
                if left <= 0:
                    return units
                piece = piece[:left]
            units.append(Unit(f"{stem}/{i // chunk:03d}", piece, module))
            if left is not None:
                left -= len(piece)
    return units


# ---------------------------------------------------------------------------- synthetic COFF targets


def _record(name: str, value: int, section: int, stype: int, storage: int, strtab: bytearray) -> bytes:
    if len(name.encode()) <= 8:
        head = name.encode().ljust(8, b"\0")
    else:
        off = len(strtab)
        strtab += name.encode() + b"\0"
        head = struct.pack("<II", 0, off)
    return head + struct.pack("<IhHBB", value, section, stype, storage, 0)


def write_coff(path: Path, text: bytes, symbols: list[tuple[str, int, int, int, int]],
               relocs: list[tuple[int, str]]) -> None:
    """A COFF object: `.text` with the given bytes, the symbols (name, value, section, type, storage) and the
    relocations (offset, symbol name) the compiler would have written."""
    strtab = bytearray(b"\0\0\0\0")
    records = _record(".text", 0, 1, 0, CLASS_STATIC, strtab)  # compilers emit the section symbol first
    index: dict[str, int] = {}
    for name, value, section, stype, storage in symbols:
        index[name] = len(records) // 18
        records += _record(name, value, section, stype, storage, strtab)
    relbytes = b"".join(struct.pack("<IIH", off, index[name], REL32) for off, name in relocs)
    hdr = 20 + 40
    reloc_off = hdr + len(text)
    sym_off = reloc_off + len(relbytes)
    out = struct.pack("<HHIIIHH", MACHINE_X64, 1, 0, sym_off, len(records) // 18, 0, 0)
    out += b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0, 0, len(text), hdr, reloc_off, 0, len(relocs), 0, 0x60500020)
    out += text + relbytes + records + struct.pack("<I", len(strtab)) + bytes(strtab[4:])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(out)


def synth_target(pe: Pe, unit: Unit, by_rva: dict[int, Fn], md, out: Path) -> dict:
    """The unit's original machine code as a COFF object: bytes, symbols, relocations, fields zeroed."""
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

    limit = max((s.vaddr + max(s.vsize, s.rsize) for s in pe.sections), default=0)
    text = bytearray()
    defined: list[tuple[str, int]] = []
    refs: dict[str, tuple[int, int, int, int]] = {}  # name -> (value, section, type, storage) for refs alone
    relocs: list[tuple[int, str]] = []
    here = {fn.flat for fn in unit.fns}
    counts = {"calls": 0, "data": 0}
    for fn in unit.fns:
        raw = bytearray(pe.read(fn.rva, fn.end - fn.rva))
        if not raw:
            continue
        base = pe.image_base + fn.rva
        offset = len(text)
        defined.append((fn.flat, offset))
        for ins in md.disasm(bytes(raw), base):
            if ins.mnemonic == "int3":
                break  # inter-function padding: what follows is another function, or an inline table
            found = []
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and ins.encoding.disp_size == 4:
                    target = ins.address + ins.size + op.mem.disp - pe.image_base
                    if not 0 <= target < limit:
                        continue  # a misdecoded byte, not a real reference
                    found.append((_ref_symbol(target, by_rva), ins.address - base + ins.encoding.disp_offset,
                                  "data", target))
                elif op.type == X86_OP_IMM and (ins.mnemonic == "call" or ins.mnemonic.startswith("j")) \
                        and ins.encoding.imm_size == 4:
                    target = op.imm - pe.image_base
                    if fn.rva <= target < fn.end:
                        continue  # branches inside the function stay relative
                    if not 0 <= target < limit:
                        continue
                    found.append((_ref_symbol(target, by_rva), ins.address - base + ins.encoding.imm_offset,
                                  "calls", target))
            for name, field, kind, target in found:
                raw[field:field + 4] = b"\0\0\0\0"
                relocs.append((offset + field, name))
                counts[kind] += 1
                if name not in here and name not in refs:
                    # COFF symbol values are 32-bit image-relative addresses; objdiff matches relocations by
                    # symbol name, so the RVA is all a data reference needs to carry.
                    refs[name] = ((target, SYM_ABSOLUTE, 0, CLASS_STATIC) if kind == "data"
                                  else (0, SYM_UNDEFINED, STYPE_FUNCTION, CLASS_EXTERNAL))
        text += raw
        text += b"\xcc" * (-len(text) % 16)  # MSVC-like padding between functions
    symbols = [(name, off, 1, STYPE_FUNCTION, CLASS_EXTERNAL) for name, off in defined]
    symbols += [(name, *refs[name]) for name in sorted(refs)]
    write_coff(out, bytes(text), symbols, relocs)
    return {"size": len(text), "functions": len(defined), "relocs": len(relocs), **counts}


def _ref_symbol(rva: int, by_rva: dict[int, Fn]) -> str:
    fn = by_rva.get(rva)
    return fn.flat if fn is not None else f"{DATA_PREFIX}{rva:x}"


def _capstone():
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


# ---------------------------------------------------------------------------- project files


BASIC_TYPES = """/* Shared types for this decompilation. Agents add structs, enums and prototypes here (or in headers
 * next to it) as they work out the layout; context.h is generated once and theirs to edit afterwards. */
#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdint.h>

typedef int8_t s8;
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;
typedef float f32;
typedef double f64;
typedef int32_t il2cpp_bool;
typedef void (*Il2CppMethodPointer)();

typedef struct Il2CppObject { void *klass; void *monitor; } Il2CppObject;
typedef struct Il2CppClass Il2CppClass;
typedef struct Il2CppString { Il2CppObject object; int32_t length; uint16_t chars[]; } Il2CppString;
typedef struct Il2CppArray { Il2CppObject object; void *bounds; intptr_t max_length; void *vector[]; } Il2CppArray;
typedef struct MethodInfo MethodInfo;
typedef struct Il2CppType Il2CppType;
typedef struct FieldInfo FieldInfo;
typedef struct Il2CppException Il2CppException;

#ifndef NULL
#define NULL 0
#endif

#endif
"""


def unit_stub(unit: Unit) -> str:
    lo, hi = unit.fns[0].rva, unit.fns[-1].end
    sample = ", ".join(fn.flat for fn in unit.fns[:3])
    return (
        f"/* {unit.name}: {len(unit.fns)} functions, 0x{lo:x}..0x{hi:x} of the original.\n"
        f" * Write each function here with its exact name: `extern \"C\" void {unit.fns[0].flat}(...)` "
        f"({sample}, ...).\n"
        f" * One function at a time: compile_and_diff replaces or appends the definition and builds this file. */\n"
        f"#include \"context.h\"\n"
    )


def write_project(root: Path, pe: Pe, fns: list[Fn], units: list[Unit], clang: str, label: str = "",
                  log=print) -> dict:
    (root / "include").mkdir(parents=True, exist_ok=True)
    by_rva = {fn.rva: fn for fn in fns}
    md = _capstone()
    totals = {"functions": 0, "relocs": 0, "calls": 0, "data": 0}
    for u in units:
        info = synth_target(pe, u, by_rva, md, root / u.target)
        for k in totals:
            totals[k] += info[k]
        src = root / u.source
        if not src.exists():  # never overwrite work agents already did
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_text(unit_stub(u), encoding="utf-8")
    if not (root / "include" / "context.h").exists():  # theirs to edit from the first minute on
        (root / "include" / "context.h").write_text(BASIC_TYPES, encoding="utf-8")
    _write_ninja(root, units, clang)
    (root / "objdiff.json").write_text(json.dumps({
        "min_version": "2.0.0", "custom_make": "ninja", "build_base": True,
        "options": {"functionRelocDiffs": "none", "combineDataSections": True, "combineTextSections": True},
        "units": [{
            "name": u.name, "target_path": u.target, "base_path": u.base,
            "metadata": {"source_path": u.source, "complete": False},
            "scratch": {"platform": "win32", "compiler": label or clang, "c_flags": " ".join(CLANG_FLAGS)},
        } for u in units],
    }, indent=2) + "\n", encoding="utf-8")
    log(f"{len(units)} source files for agents to write into ({len(fns)} functions)")
    return totals


def _quote(cmd: str) -> str:
    return f'"{cmd}"' if " " in cmd else cmd


def _write_ninja(root: Path, units: list[Unit], compiler: str) -> None:
    lines = ["ninja_required_version = 1.10", "", "rule cc",
             f"  command = {_quote(compiler)} {' '.join(CLANG_FLAGS)} $in -o $out", "  description = cc $in", ""]
    lines += [f"build {u.base}: cc {u.source}" for u in units]
    lines += ["", "build all_source: phony " + " ".join(u.base for u in units), "", "default all_source", ""]
    (root / "build.ninja").write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------- driver


def find_clang() -> str:
    """The x86-64 Windows-capable C++ compiler to build units with, from PATH."""
    for name in ("clang++", "clang"):
        found = shutil.which(name)
        if found:
            return found
    raise UnityError("this needs clang to build the project's units: install LLVM (clang) and try again")


def clang_version(clang: str) -> str:
    try:
        res = subprocess.run([clang, "--version"], capture_output=True, text=True, timeout=20,
                             encoding="utf-8", errors="replace")
        m = re.search(r"clang version (\S+)", res.stdout)
        return m.group(1) if m else "clang"
    except (OSError, subprocess.TimeoutExpired):
        return "clang"


def generate(root: Path, dll: Path, *, symbols: list[Path] | None = None,
             max_functions: int | None = DEFAULT_MAX_FUNCTIONS, chunk: int = DEFAULT_CHUNK,
             compiler: str | None = None, log=print) -> dict:
    """Write the whole project in `root`: targets, sources, objdiff.json and the ninja build."""
    pe = Pe.load(dll)
    if pe.machine != MACHINE_X64:
        raise UnityError(f"{dll.name} is not a 64-bit x86 Windows program (PE machine 0x{pe.machine:04x}): only "
                         "Windows x64 Unity IL2CPP builds are supported so far")
    maps: list[Path] = []
    for p in (symbols or []) + find_symbol_files(dll.parent):
        found = find_symbol_files(p) if p.is_dir() else ([p] if p.is_file() else [])
        for f in found:
            if f not in maps:
                maps.append(f)
    names, mods = load_symbol_map(maps)
    fns = build_inventory(pe, names, mods)
    if not fns:
        raise UnityError(f"{dll.name} has no function boundaries (.pdata): not a Unity IL2CPP program?")
    units = plan_units(fns, chunk=chunk, max_functions=max_functions)
    clang = compiler or find_clang()
    label = f"{Path(clang).name} {clang_version(clang)}"
    log(f"{dll.name}: {len(fns)} functions ({sum(f.named for f in fns)} named), "
        f"{len(units)} source files to work on, symbol maps: {', '.join(p.name for p in maps) or 'none'}")
    totals = write_project(root, pe, fns, units, clang, label=label, log=log)
    (root / "tools").mkdir(exist_ok=True)
    (root / "tools" / "il2cppsplit.py").write_text(WRAPPER, encoding="utf-8")
    (root / "tools" / "inventory.json").write_text(json.dumps({
        "functions": len(fns), "named": sum(f.named for f in fns), "units": len(units), "compiler": label,
        "modules": {m: sum(1 for f in fns if f.module == m) for m in sorted({f.module for f in fns})},
    }, indent=2), encoding="utf-8")
    return {"functions": len(fns), "named": sum(f.named for f in fns), "units": len(units),
            "compiler": label, "totals": totals, "modules": len({f.module for f in fns})}


WRAPPER = '''#!/usr/bin/env python3
"""Regenerate this project's units and targets from the game's GameAssembly.dll (decomp.wtf)."""
import sys

from decompnet.forks import il2cppsplits

if __name__ == "__main__":
    sys.exit(il2cppsplits.main(["--game", "orig", *sys.argv[1:]]))
'''


# ---------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    """Regenerate a project from a GameAssembly.dll (used by the wrapper inside generated projects)."""
    ap = argparse.ArgumentParser(description="Create or refresh a Unity IL2CPP decompilation project")
    ap.add_argument("--game", required=True, help="the game folder, or a GameAssembly.dll")
    ap.add_argument("--out", default=".", help="where to write the project (default: current directory)")
    ap.add_argument("--symbols", action="append", default=[], help="symbols.txt/methods_final.json (or their folder)")
    ap.add_argument("--all", action="store_true", help="every function; default: the first --max by priority")
    ap.add_argument("--max", type=int, default=DEFAULT_MAX_FUNCTIONS, help="how many functions to include")
    ap.add_argument("--chunk", type=int, default=DEFAULT_CHUNK, help="functions per source file")
    args = ap.parse_args(argv)
    where = Path(args.game).expanduser()
    dll = where if where.is_file() else where / "GameAssembly.dll"
    if not dll.is_file():
        print(f"no GameAssembly.dll at {dll}", file=sys.stderr)
        return 2
    symbols: list[Path] = []
    for s in args.symbols:
        p = Path(s).expanduser()
        symbols += [p] if p.is_file() else find_symbol_files(p)
    try:
        stats = generate(Path(args.out), dll, symbols=symbols, max_functions=None if args.all else args.max,
                         chunk=args.chunk)
    except UnityError as e:
        print(e, file=sys.stderr)
        return 1
    print(f"{stats['functions']} functions, {stats['units']} source files, compiler {stats['compiler']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
