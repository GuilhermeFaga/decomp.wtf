"""Unity IL2CPP (Windows x64) from scratch: a project generated from the game's own GameAssembly.dll.

The test synthesizes a small PE (`GameAssembly.dll`) with x64 unwind tables (.pdata) and four functions —
one plain, one that calls it and loads a data global (`[rip+disp]`), one unnamed, one leaf without unwind
info — plus the symbol maps a RE session leaves behind (`symbols.txt`, `methods_final.json`), and checks that
decomp.wtf detects the game, builds the inventory, writes the objdiff project and imports it like any fork.

With clang, ninja and objdiff-cli installed it goes further: it compiles a function itself, uses those exact
bytes as the original and has an agent match it byte for byte through `compile_and_diff`.
"""

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.app.engine import RomNetwork
from decompnet.forks import coff, ghidra, il2cppsplits, scratch_unity
from decompnet.forks.project import ForkProject
from decompnet.network import NetworkError

IMAGE_BASE = 0x180000000
NAMES = {0x1000: "TestNs_Alpha_Sum", 0x1010: "TestNs_Beta_Run", 0x1040: "TestNs_Gamma_Leaf"}
needs_clang = pytest.mark.skipif(shutil.which("clang++") is None, reason="needs clang++")
needs_tools = pytest.mark.skipif(
    toolchains.installed("objdiff-cli") is None or shutil.which("clang++") is None or shutil.which("ninja") is None,
    reason="needs objdiff-cli, clang++ and ninja")


# ---------------------------------------------------------------------------- a synthetic Unity game


def _section(name: str, vaddr: int, vsize: int, raw: int, rsize: int, chars: int) -> bytes:
    return name.encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", vsize, vaddr, rsize, raw, 0, 0, 0, 0, chars)


def _pe(sections: list[tuple[str, int, bytes, int]], dirs: dict[int, tuple[int, int]]) -> bytes:
    """A minimal PE32+ whose sections are (name, vaddr, data, characteristics)."""
    nsec = len(sections)
    optsize = 240
    headers = 0x200
    raw = headers
    placed = []
    for name, vaddr, data, chars in sections:
        placed.append((name, vaddr, len(data), data, raw, max(len(data), 0x200), chars))
        raw += max(len(data), 0x200)
    out = bytearray(raw)  # headers + one raw block per section
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x40)
    out[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", out, 0x44, 0x8664, nsec, 0, 0, 0, optsize, 0x22)
    opt = 0x58
    struct.pack_into("<H", out, opt, 0x20B)
    struct.pack_into("<Q", out, opt + 24, IMAGE_BASE)
    struct.pack_into("<II", out, opt + 32, 0x1000, 0x200)  # section/file alignment
    struct.pack_into("<I", out, opt + 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", out, opt + 60, headers)  # SizeOfHeaders
    struct.pack_into("<H", out, opt + 68, 3)  # Subsystem
    struct.pack_into("<I", out, opt + 108, 6)
    for i, (rva, size) in dirs.items():
        struct.pack_into("<II", out, opt + 112 + i * 8, rva, size)
    so = opt + optsize
    for i, (name, vaddr, vsize, data, off, rsize, chars) in enumerate(placed):
        out[so + i * 40:so + (i + 1) * 40] = _section(name, vaddr, vsize, off, rsize, chars)
    for _, _, vsize, data, off, _, _ in placed:
        out[off:off + vsize] = data
    return bytes(out)


def _demo_dll() -> bytes:
    text = bytearray(0x46)
    a = bytes.fromhex("4883ec28b82a0000004883c428c3")  # sub rsp,0x28; mov eax,0x2a; add rsp,0x28; ret
    b = bytearray(bytes.fromhex("4883ec28e8e7ffffff488b05e01f00004883c428c3"))  # call Sum, mov rax,[rip+0x3000]
    d = bytes.fromhex("31c0c3")  # xor eax,eax; ret (no name)
    c = bytes.fromhex("b807000000c3")  # mov eax,7; ret (leaf: no unwind info)
    text[0x00:0x00 + len(a)] = a
    text[0x10:0x10 + len(b)] = b
    text[0x30:0x30 + len(d)] = d
    text[0x40:0x40 + len(c)] = c
    pdata = b"".join(struct.pack("<III", beg, end, 0) for beg, end in
                     ((0x1000, 0x1010), (0x1010, 0x1030), (0x1030, 0x1040))) + struct.pack("<III", 0, 0, 0)
    rdata = struct.pack("<d", 1.5)
    return _pe([(".text", 0x1000, bytes(text), 0x60000020), (".pdata", 0x2000, pdata, 0x40000040),
                (".rdata", 0x3000, rdata, 0x40000040)], {3: (0x2000, len(pdata))})


def make_game(tmp_path: Path, name: str = "Demo Game", dll: bytes | None = None,
              names: dict[int, str] | None = None) -> Path:
    """A Unity game folder: GameAssembly.dll, the _Data folder (app.info, version, metadata) and symbol maps."""
    names = names if names is not None else NAMES
    folder = tmp_path / name
    data = folder / f"{name}_Data"
    (data / "il2cpp_data" / "Metadata").mkdir(parents=True)
    (folder / "GameAssembly.dll").write_bytes(dll if dll is not None else _demo_dll())
    (data / "app.info").write_text("Demo Studio\nDemo Game\n", encoding="utf-8")
    (data / "globalgamemanagers").write_bytes(b"\0" * 0x40 + b"2021.3.45f2\0" + b"\0" * 0x100)
    (data / "il2cpp_data" / "Metadata" / "global-metadata.dat").write_bytes(b"\xaf\x1b\xb1\xfa" + b"\0" * 64)
    (folder / "symbols.txt").write_text("".join(f"{rva:x}\t{nm}\n" for rva, nm in sorted(names.items())),
                                        encoding="utf-8")
    (folder / "methods_final.json").write_text(json.dumps([
        {"i": i, "mod": "Assembly-CSharp.dll", "name": nm.split("_")[-1], "type": "_".join(nm.split("_")[:-1]),
         "idx": i, "rva": rva, "tok": 0x06000001 + i}
        for i, (rva, nm) in enumerate(sorted(names.items()))]), encoding="utf-8")
    return folder


def coff_symbols(path: Path) -> dict[str, int]:
    """Name -> value of a COFF object's symbol table (aux records skipped)."""
    d = path.read_bytes()
    symoff, nsym = struct.unpack_from("<II", d, 8)
    strtab = d[symoff + 18 * nsym:]
    out, i = {}, 0
    while i < nsym:
        o = symoff + 18 * i
        name = d[o:o + 8]
        if name[:4] == b"\0\0\0\0":
            off, = struct.unpack_from("<I", name, 4)
            nm = strtab[off:strtab.index(b"\0", off)].decode()
        else:
            nm = name.rstrip(b"\0").decode()
        value, section = struct.unpack_from("<Ih", d, o + 8)
        storage, naux = d[o + 16], d[o + 17]
        if not nm.startswith(".") and storage in (2, 3):
            out[nm] = value
        i += 1 + naux
    return out


# ---------------------------------------------------------------------------- detection and the project


def test_a_unity_folder_is_recognised(tmp_path):
    game = make_game(tmp_path)
    assert scratch_unity.is_unity(game) and scratch_unity.is_unity(game / "GameAssembly.dll")
    assert not scratch_unity.is_unity(tmp_path / "nothing" / "GameAssembly.dll")
    other = tmp_path / "other.dll"
    other.write_bytes(b"MZ" + b"\0" * 0x10000)
    assert not scratch_unity.is_unity(other)
    info = scratch_unity.game_info(game)
    assert info["platform"] == "win32" and info["title"] == "Demo Game" and info["unity"] == "2021.3.45f2"
    assert info["sha1"] and info["metadata"] and not info["protected"]


def test_inventory_and_target_objects(tmp_path):
    game = make_game(tmp_path)
    pe = il2cppsplits.Pe.load(game / "GameAssembly.dll")
    assert pe.image_base == IMAGE_BASE
    names, mods = il2cppsplits.load_symbol_map(il2cppsplits.find_symbol_files(game))
    fns = il2cppsplits.build_inventory(pe, names, mods)
    by_rva = {f.rva: f for f in fns}
    assert sorted(by_rva) == [0x1000, 0x1010, 0x1030, 0x1040]
    assert by_rva[0x1000].flat == "TestNs_Alpha_Sum" and by_rva[0x1000].module == "Assembly-CSharp.dll"
    assert by_rva[0x1010].end == 0x1030
    assert by_rva[0x1030].name == "func_1030" and not by_rva[0x1030].named  # no unwind info in the map
    assert by_rva[0x1040].end == 0x1046  # leaf: ends at the end of the section

    root = tmp_path / "proj"
    stats = il2cppsplits.generate(root, game / "GameAssembly.dll")
    assert stats["functions"] == 4 and stats["named"] == 3 and stats["units"] == 2
    cfg = json.loads((root / "objdiff.json").read_text())
    units = {u["name"]: u for u in cfg["units"]}
    assert set(units) == {"Assembly-CSharp/000", "engine/000"}
    assert units["Assembly-CSharp/000"]["metadata"]["source_path"] == "src/Assembly-CSharp/000.cpp"
    assert (root / "include" / "context.h").is_file() and "Il2CppObject" in (root / "include" / "context.h").read_text()
    assert (root / "build.ninja").is_file() and "build all_source: phony" in (root / "build.ninja").read_text()
    src = (root / "src" / "Assembly-CSharp" / "000.cpp").read_text()
    assert "TestNs_Alpha_Sum" in src and "TestNs_Beta_Run" in src  # what to write, and its exact name
    syms = coff_symbols(root / "target" / "Assembly-CSharp" / "000.obj")
    assert [n for n in syms if n.startswith("TestNs")] == ["TestNs_Alpha_Sum", "TestNs_Beta_Run", "TestNs_Gamma_Leaf"]
    assert "data_3000" in syms and "func_1030" not in syms
    # the call's and the data reference's fields are zeroed, the instruction bytes stay
    text = (root / "target" / "Assembly-CSharp" / "000.obj").read_bytes()
    assert struct.pack("<i", -25) not in text and struct.pack("<i", 0x1fe0) not in text


def test_generate_from_a_protected_game_folder_keeps_names(tmp_path, monkeypatch):
    """The Apogea case: metadata is protected, the names come from the map a RE session produced."""
    game = make_game(tmp_path)
    meta = game / "Demo Game_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
    meta.write_bytes(b"\x0f\x57\x42\x32" + b"\0" * 64)  # not the standard magic
    assert scratch_unity.game_info(game)["protected"]
    monkeypatch.setenv(scratch_unity.SYMBOLS_ENV, str(game / "symbols.txt"))
    info = scratch_unity.game_info(game)
    assert info["symbols"] and info["symbols"][0].name == "symbols.txt"


# ---------------------------------------------------------------------------- build, import, match


@needs_tools
def test_project_builds_and_reports(tmp_path):
    game = make_game(tmp_path)
    root = tmp_path / "proj"
    il2cppsplits.generate(root, game / "GameAssembly.dll", log=lambda *_: None)
    fp = ForkProject(root)
    ok, out = fp.build_all()
    assert ok, out
    assert all(fp.unit(u.name).base.exists() for u in fp.units())
    rep = fp.report()
    assert rep["measures"]["total_functions"] == 4
    unit = fp.unit("Assembly-CSharp/000")
    d = fp.diff(unit, "TestNs_Beta_Run")
    assert d.match_percent is None  # the base object exists, the function isn't written yet


@needs_tools
def test_import_claim_and_match(tmp_path):
    """The F1 loop: import a game folder, claim a function, write it, and match it byte for byte."""
    root_cc = Path(__file__).resolve().parent.parent
    game = make_game(tmp_path)
    base = tmp_path / "app"
    base.mkdir()
    net = RomNetwork(base / "app.db", base / "work")
    slug = net.import_rom(game, confirmed=True, log=lambda *_: None)
    ov = net.overview(slug)
    assert ov["kind"] == "fork" and ov["origin"] == "scratch" and ov["ready"]
    assert ov["platform"] == "win32" and ov["unity"] == "2021.3.45f2"
    assert ov["functions"] == 4
    assert "started from scratch" in net.forks.info(slug)
    fp = net.forks.get(slug)[1]
    files = subprocess.run(["git", "ls-files"], cwd=fp.root, capture_output=True, text=True).stdout.split()
    assert "include/context.h" in files and "objdiff.json" in files
    assert not [f for f in files if f.startswith(("orig/", "build/", "target/"))]

    agent, _ = net.local_agent("unity-agent")
    claim = net.forks.claim(agent, slug, "TestNs_Beta_Run")
    assert "TestNs_Beta_Run" in claim and "### Target assembly" in claim and "call TestNs_Alpha_Sum" in claim
    edit = net.forks.edit_file(agent, slug, "src/Assembly-CSharp/000.cpp", "",
                               'extern "C" void TestNs_Alpha_Sum(void);\nextern "C" double data_3000[];',
                               "declare the function it calls and the global it reads")
    assert edit.startswith("✅"), edit
    code = ("extern \"C\" void TestNs_Beta_Run(void *self) {\n"
            "    TestNs_Alpha_Sum();\n"
            "    *(double *)0 = data_3000[0];\n"
            "    *(double *)(*(char **)self) = 2.0;\n"
            "}\n")
    res = net.attempt(agent, "TestNs_Beta_Run", code, slug)
    assert res["score"] is not None and not res["matched"], res["text"]  # the shape is right, the code isn't

    # A function whose original bytes the test compiles itself: the same source must match 100%.
    cc = shutil.which("clang++")
    obj, source = tmp_path / "mul.obj", 'extern "C" int Demo_Mul(int a, int b) { return a * b + 3; }\n'
    src_file = tmp_path / "mul.cpp"
    src_file.write_text(source)
    flags = [f for f in il2cppsplits.CLANG_FLAGS if f != "-Iinclude"]
    subprocess.run([cc, *flags, str(src_file), "-o", str(obj)], check=True, cwd=tmp_path)
    d = obj.read_bytes()
    text = b""
    for i in range(struct.unpack_from("<H", d, 2)[0]):
        o = 20 + i * 40
        if d[o:o + 8].rstrip(b"\0") == b".text":
            _, vsize, rsize, raw = struct.unpack_from("<IIII", d, o + 8)
            text = d[raw:raw + rsize]
    assert text, "clang made no .text"
    got = tmp_path / "got"
    got.mkdir()
    game2 = make_game(got, name="MulGame", dll=_pe(
        [(".text", 0x1000, text + b"\xcc" * (-len(text) % 16), 0x60000020),
         (".pdata", 0x2000, struct.pack("<III", 0x1000, 0x1000 + len(text), 0) + struct.pack("<III", 0, 0, 0),
          0x40000040)],
        {3: (0x2000, 24)}), names={0x1000: "Demo_Mul"})
    slug2 = net.import_rom(game2, confirmed=True, log=lambda *_: None)
    agent2, _ = net.local_agent("unity-agent-2")
    res = net.attempt(agent2, "Demo_Mul", source, slug2)
    assert res["matched"], res["text"]


@needs_tools
def test_names_outside_the_project_say_what_to_do(tmp_path):
    """The Apogea case: target assembly calls functions the project's units don't cover (still named
    `func_<address>`), and agents try to open them. get_function points at what exists, or says the call is
    written by hand instead of leaving the agent to guess."""
    game = make_game(tmp_path)
    base = tmp_path / "app"
    base.mkdir()
    net = RomNetwork(base / "app.db", base / "work")
    slug = net.import_rom(game, confirmed=True, log=lambda *_: None)
    agent, _ = net.local_agent("unity-agent")
    with pytest.raises(NetworkError, match="Closest function: func_1030"):
        net.forks.get_function(agent, slug, "func_1020")  # the gap between two functions
    with pytest.raises(NetworkError, match="list_functions"):
        net.forks.get_function(agent, slug, "func_9999")  # nothing of the project anywhere near


def test_a_unit_object_says_what_it_calls(tmp_path):
    """Autopilot declares a unit's externals before a Ghidra draft calls them, and they come from the target
    object's symbol table (data references are absolute symbols there, calls undefined functions)."""
    game = make_game(tmp_path)
    root = tmp_path / "proj"
    il2cppsplits.generate(root, game / "GameAssembly.dll", log=lambda *_: None)
    funcs, data = coff.externals(root / "target" / "Assembly-CSharp" / "000.obj")
    assert (funcs, data) == ([], ["data_3000"])
    assert 'extern "C" unsigned char data_3000;' in ghidra.declarations(funcs, data, cpp=True)
    header = root / "include" / "context.h"
    assert ghidra.add_types(header) and "GHIDRA_DEFINES" in header.read_text()
    assert not ghidra.add_types(header)  # once is enough


@needs_clang
def test_the_ghidra_block_compiles_a_draft(tmp_path):
    """A draft only gets anywhere if it builds: Ghidra's types, its CONCAT/SUB/ZEXT helpers and `code` (called
    through with arguments) have to compile as C++ against the header drafts are written into."""
    header = tmp_path / "context.h"
    header.write_text(ghidra.TYPES, encoding="utf-8")
    draft = tmp_path / "draft.cpp"
    draft.write_text('#include "context.h"\n'
                     'extern "C" unsigned long long caller(undefined8 p, ulong n) {\n'
                     "  code *fn = (code *)CONCAT44(n, p);\n"
                     "  (*fn)(p, 1, 2);\n"
                     "  return ZEXT48(SUB84(p, 0)) + CONCAT31(p, 7) + SEXT48(p);\n"
                     "}\n", encoding="utf-8")
    subprocess.run(["clang++", "--target=x86_64-pc-windows-msvc", "-O2", "-std=c++17", "-I", str(tmp_path),
                    str(draft), "-c", "-o", str(tmp_path / "draft.obj")], check=True)


@needs_tools
def test_autopilot_takes_a_ghidra_platform(tmp_path, monkeypatch):
    """Windows x86-64: m2c can't read it, so the drafts come from Ghidra. Autopilot says so when Ghidra is
    missing, takes the project when it's there (adding Ghidra's types to the header), and declares the unit's
    externals once so a draft that calls them compiles."""
    game = make_game(tmp_path)
    base = tmp_path / "app"
    base.mkdir()
    net = RomNetwork(base / "app.db", base / "work")
    slug = net.import_rom(game, confirmed=True, log=lambda *_: None)
    monkeypatch.setattr(ghidra, "available", lambda: False)
    with pytest.raises(NetworkError, match="come from Ghidra"):
        net.forks.autopilot_prepare(slug)
    monkeypatch.undo()
    if not ghidra.available():
        pytest.skip("needs Ghidra and Java 21")
    assert len(net.forks.autopilot_prepare(slug)) == 4
    root = Path(net.project_row(slug)["root"])
    assert "GHIDRA_DEFINES" in (root / "include" / "context.h").read_text()
    agent, _ = net.local_agent("autopilot")
    fp = net.forks.get(slug)[1]
    source = root / "src" / "Assembly-CSharp" / "000.cpp"
    net.forks._prepare_draft_decls(agent, net.project_row(slug), fp, fp.unit("Assembly-CSharp/000"))
    assert 'extern "C" unsigned char data_3000;' in source.read_text()
    net.forks._prepare_draft_decls(agent, net.project_row(slug), fp, fp.unit("Assembly-CSharp/000"))
    assert 'data_3000;' in source.read_text() and source.read_text().count("data_3000;") == 1
