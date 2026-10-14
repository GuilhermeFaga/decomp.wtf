"""Start a Unity (IL2CPP) decompilation from the user's own game folder: gen an objdiff project for it.

The user drops the folder of a Unity game (or its `GameAssembly.dll`). decomp.wtf finds the functions from the
PE's unwind tables, names them from the metadata (or from a symbol map left in the folder: `symbols.txt` /
`methods_final.json`, or a folder named in $DECOMPWTF_UNITY_SYMBOLS), writes one synthetic COFF target per
source file (original bytes, symbols and relocations) and a clang/ninja build for the base objects. The fork
engine then works on it like on any community decomp: agents claim functions, write C/C++ into `src/`, and
objdiff scores every function.

The game's files stay in `orig/` (out of git and out of exports); only the function inventory and the target
objects are derived data.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

from . import il2cppsplits
from .project import ForkError, ForkProject

METADATA = Path("il2cpp_data") / "Metadata" / "global-metadata.dat"
SYMBOLS_ENV = "DECOMPWTF_UNITY_SYMBOLS"


def _is_gameassembly(path: Path) -> bool:
    """A Windows PE with x64 unwind tables (or an il2cpp section): the GameAssembly.dll of a Unity build."""
    try:
        if path.stat().st_size < 0x400:
            return False
        pe = il2cppsplits.Pe.load(path)
    except (OSError, il2cppsplits.UnityError, struct.error):
        return False
    if pe.machine not in (il2cppsplits.MACHINE_X64, il2cppsplits.MACHINE_X86):
        return False
    return pe.has_il2cpp_section or bool(il2cppsplits.read_pdata(pe))


def is_unity(path: Path) -> bool:
    """Whether this is a Unity game folder (or a GameAssembly.dll) decomp.wtf can start from."""
    p = Path(path)
    if p.is_dir():
        return _is_gameassembly(p / "GameAssembly.dll")
    return p.name.lower() == "gameassembly.dll" and _is_gameassembly(p)


def _data_dirs(folder: Path) -> list[Path]:
    return sorted(p for p in folder.glob("*_Data") if p.is_dir()) if folder.is_dir() else []


def _title(folder: Path, fallback: str) -> str:
    """The game's name: app.info has the company and then the product (newer Unity: only the product)."""
    for data in _data_dirs(folder):
        info = data / "app.info"
        if info.is_file():
            lines = [ln.strip() for ln in info.read_text(errors="replace", encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                return lines[-1]
    return fallback


def _unity_version(folder: Path) -> str:
    for data in _data_dirs(folder):
        ggm = data / "globalgamemanagers"
        if ggm.is_file():
            try:
                head = ggm.read_bytes()[:4096]
            except OSError:
                continue
            m = re.search(rb"(20\d\d\.\d+\.\d+[abfp]\d+)", head)
            if m:
                return m.group(1).decode()
    return ""


def _metadata(folder: Path) -> Path | None:
    for data in _data_dirs(folder):
        p = data / METADATA
        if p.is_file():
            return p
    return None


def game_info(path: Path) -> dict:
    """What the user dropped: {"platform": "win32", "id", "title", "sha1", "dll", "folder", ...}."""
    p = Path(path).expanduser()
    folder = p if p.is_dir() else p.parent
    dll = p if p.is_file() else p / "GameAssembly.dll"
    if not dll.is_file():
        raise ForkError(f"no GameAssembly.dll at {folder}")
    pe = il2cppsplits.Pe.load(dll)
    meta = _metadata(folder)
    symbols = il2cppsplits.find_symbol_files(folder)
    env = os.environ.get(SYMBOLS_ENV)
    if env:
        env_path = Path(env).expanduser()
        symbols += [env_path] if env_path.is_file() else il2cppsplits.find_symbol_files(env_path)
    symbols = list(dict.fromkeys(symbols))
    return {
        "platform": "win32", "kind": "unity", "title": _title(folder, folder.name),
        "id": _unity_version(folder) or "unity", "unity": _unity_version(folder),
        "sha1": hashlib.sha1(dll.read_bytes()).hexdigest(), "dll": dll, "folder": folder,
        "metadata": meta, "symbols": symbols, "il2cpp": pe.has_il2cpp_section,
        "protected": bool(meta and meta.read_bytes()[:4] != b"\xaf\x1b\xb1\xfa"),
    }


def tool_args() -> list[str]:
    """Extra configure-time arguments for setup commands: nothing (the build is just ninja)."""
    return []


def _place(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    try:
        os.link(src, dest)  # no second copy of a 40 MB DLL when it's on the same drive
    except OSError:
        shutil.copyfile(src, dest)


def create(root: Path, game: Path, *, compiler: str | None = None,
           max_functions: int | None = il2cppsplits.DEFAULT_MAX_FUNCTIONS,
           symbols: list[Path] | None = None, log=print) -> dict:
    """Make the project in `root` (which must not exist yet) and build it once. Returns facts about the game."""
    info = game_info(game)
    root.mkdir(parents=True, exist_ok=True)
    _place(info["dll"], root / "orig" / "GameAssembly.dll")
    if info["metadata"] is not None:
        _place(info["metadata"], root / "orig" / "global-metadata.dat")
    stats = il2cppsplits.generate(root, info["dll"], symbols=symbols or info["symbols"],
                                  max_functions=max_functions, compiler=compiler, log=log)
    _write_readme(root, info, stats)
    (root / ".decomp.wtf.json").write_text(json.dumps({
        "created": "from scratch", "platform": "win32", "unity": info["unity"],
        "compiler": stats["compiler"],
        "game": {"what": "your copy of the game (GameAssembly.dll and the _Data folder)",
                 "path": "orig/GameAssembly.dll", "sha1": info["sha1"],
                 "help": "Point decomp.wtf at the game's GameAssembly.dll (or its folder) again if this copy is gone."},
        "setup": [["ninja"]],
    }, indent=2) + "\n", encoding="utf-8")
    with open(root / ".gitignore", "a", encoding="utf-8") as f:
        f.write("\n# decomp.wtf\n.decomp-wtf/\norig/\nbuild/\ntarget/\n")
    fp = ForkProject(root)
    log("compiling every source file, so objdiff can measure each one")
    ok, tail = fp.build_all(log=log)
    if not ok:
        raise ForkError(f"the project's first build didn't work (clang-target x86-64 Windows):\n{tail[-1500:]}")
    if shutil.which("git"):
        for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                    ["git", "-c", "user.name=decomp.wtf", "-c", "user.email=noreply@decomp.wtf", "commit", "-q",
                     "-m", f"Start the {info['title']} decompilation (decomp.wtf, Unity IL2CPP)"]):
            subprocess.run(cmd, cwd=root, capture_output=True)
    return {"platform": "win32", "id": info["id"], "title": info["title"], "compiler": stats["compiler"],
            "unity": info["unity"], "functions": stats["functions"], "named": stats["named"],
            "sources": stats["units"]}


def _write_readme(root: Path, info: dict, stats: dict) -> None:
    maps = ", ".join(p.name for p in info["symbols"]) or "none (functions are func_<address>)"
    (root / "README.md").write_text(f"""# {info['title']} — Unity IL2CPP decompilation

Started from the game's own `GameAssembly.dll` with [decomp.wtf](https://decomp.wtf). Unity {info['unity'] or '?'}.
The DLL and metadata stay in `orig/` (git-ignored, never exported); the original function bytes live in
`target/` objects, derived data.

- `src/`: the decompilation, one file per assembly (or engine cluster). Agents write functions here with the
  exact name from the inventory (`extern "C"`), e.g. `Namespace_Type_Method`.
- `objdiff.json` + `build.ninja`: clang targeting x86-64 Windows builds each file; `ninja` builds everything.
- `include/context.h`: shared types; extend it as struct layouts become clear.
- `tools/il2cppsplit.py`: regenerates the project from `orig/GameAssembly.dll` (targets, units, `objdiff.json`;
  source files you already wrote are kept).
  Options: `--all` (every function), `--max N`, `--chunk N`, `--symbols <symbols.txt|methods_final.json|dir>`.

{stats['functions']} functions in the inventory ({stats['named']} named), {stats['units']} source files to start
from. Symbol maps: {maps}.

This is a diff-only project: there is no final link of the original program yet, so a function is done when
objdiff says 100%; `compile_and_diff` records those as matched.
""", encoding="utf-8")
