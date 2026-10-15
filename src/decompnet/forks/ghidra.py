"""Ghidra drafts: decompiled C for platforms m2c doesn't read (x86, AArch64, Xbox 360 PowerPC, SuperH...).

Optional: Ghidra is large (540 MB) and needs Java 21+. Headless Ghidra analyses a unit's target object once
and decompiles all its functions; the result is cached next to the project, so the cost (tens of seconds,
mostly starting the JVM) is paid once per source file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from importlib import resources
from pathlib import Path

from .. import toolchains
from ..limits import capped


def available() -> bool:
    return toolchains.installed("ghidra") is not None and toolchains.java_version() >= 21


# What Ghidra's C needs to compile as it is: its names for what it can't type, its helpers for concatenating
# and splitting registers, and its spelling of a software interrupt (x86 `int3`). Written for decomp.wtf;
# autopilot tries drafts without an agent, so the approximations only have to build and be close (a match is
# byte-identical or it isn't a match).
TYPES = """\
#ifndef GHIDRA_DEFINES
#define GHIDRA_DEFINES
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char uchar;
typedef signed char sbyte;
typedef unsigned char byte;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long long qword;
#ifdef __cplusplus
typedef void code(...);  /* any arguments: Ghidra calls through it without knowing the signature */
#else
typedef void code();
#endif
#define CONCAT11(a, b) ((((unsigned int)(unsigned char)(a)) << 8) | (unsigned char)(b))
#define CONCAT12(a, b) ((((unsigned int)(unsigned char)(a)) << 16) | (unsigned short)(b))
#define CONCAT13(a, b) ((((unsigned int)(unsigned char)(a)) << 24) | ((unsigned int)(b) & 0xffffff))
#define CONCAT14(a, b) ((((unsigned long long)(unsigned char)(a)) << 32) | (unsigned int)(b))
#define CONCAT21(a, b) ((((unsigned int)(unsigned short)(a)) << 8) | (unsigned char)(b))
#define CONCAT22(a, b) ((((unsigned int)(unsigned short)(a)) << 16) | (unsigned short)(b))
#define CONCAT24(a, b) ((((unsigned long long)(unsigned short)(a)) << 32) | (unsigned int)(b))
#define CONCAT31(a, b) ((((unsigned int)(a) & 0xffffff) << 8) | (unsigned char)(b))
#define CONCAT41(a, b) ((((unsigned long long)(unsigned int)(a)) << 8) | (unsigned char)(b))
#define CONCAT44(a, b) ((((unsigned long long)(unsigned int)(a)) << 32) | (unsigned int)(b))
#define SUB41(a, b) ((unsigned char)(a) - (unsigned char)(b))
#define SUB42(a, b) ((unsigned short)(a) - (unsigned short)(b))
#define SUB84(a, b) ((unsigned long long)(a) - (unsigned long long)(b))
#define ZEXT14(a) ((unsigned int)(unsigned char)(a))
#define ZEXT18(a) ((unsigned long long)(unsigned char)(a))
#define ZEXT24(a) ((unsigned int)(unsigned short)(a))
#define ZEXT28(a) ((unsigned long long)(unsigned short)(a))
#define ZEXT48(a) ((unsigned long long)(unsigned int)(a))
#define SEXT14(a) ((int)(signed char)(a))
#define SEXT18(a) ((long long)(signed char)(a))
#define SEXT24(a) ((int)(short)(a))
#define SEXT48(a) ((long long)(int)(a))
#define swi(n) (0)
#endif
"""


def add_types(header: Path) -> bool:
    """The types and macros Ghidra's C uses, added to a from-scratch project's shared header. False when
    they're there already."""
    try:
        text = header.read_text(encoding="utf-8")
    except OSError:
        return False
    if "GHIDRA_DEFINES" in text:
        return False
    block = "\n/* What machine drafts (Ghidra) need for their own types and helpers. */\n" + TYPES
    end = text.rstrip().rfind("#endif")
    text = text[:end] + block + "\n" + text[end:] if end >= 0 else text.rstrip("\n") + "\n" + block
    header.write_text(text, encoding="utf-8")
    return True


def _close_paren(text: str, open_at: int) -> int:
    depth, i = 0, open_at
    while i < len(text):
        depth += (text[i] == "(") - (text[i] == ")")
        i += 1
        if depth == 0:
            break
    return i


def prototype(draft: str, name: str) -> str | None:
    """`type name(parameters);` from a draft's definition of `name`, or None when the draft has no definition
    of it. Used to declare a draft's same-unit callees inside its own body: C++ wants them before use, and a
    block-scope declaration carries the C linkage the target's symbol has."""
    m = re.search(rf"(?<![\w:~]){re.escape(name)}\s*\(", draft)
    if m is None:
        return None
    start = draft.rfind("\n", 0, m.start()) + 1
    head = " ".join(draft[start:_close_paren(draft, m.end() - 1)].split())
    return f"{head};" if head and "{" not in head and ";" not in head else None


def arg_count(text: str, name: str) -> int | None:
    """How many arguments the first call `name(...)` in the text passes, or None when it isn't called."""
    m = re.search(rf"(?<![\w:~]){re.escape(name)}\s*\(", text)
    if m is None:
        return None
    end = _close_paren(text, m.end() - 1)
    inside, depth, commas = text[m.end():end - 1], 0, 0
    for c in inside:
        depth += (c == "(") - (c == ")")
        if c == "," and depth == 0:
            commas += 1
    return commas + 1 if inside.strip() else 0


def param_count(proto: str) -> int:
    """How many parameters a prototype declares (`void` and `()` count zero, `(...)` counts as -1)."""
    start = proto.find("(")
    inside = proto[start + 1:proto.rfind(")")].strip()
    if not inside or inside == "void":
        return 0
    if inside == "...":
        return -1
    depth, commas = 0, 0
    for c in inside:
        depth += (c == "(") - (c == ")")
        if c == "," and depth == 0:
            commas += 1
    return commas + 1


def declarations(funcs: list[str], data: list[str], cpp: bool = False) -> str:
    """A block declaring what a unit's code calls but doesn't define, as loosely as the language allows: a
    Ghidra draft calls them by name knowing nothing about their signatures. `cpp`: the unit is C++ (its
    functions take anything through `(...)` and its data needs `extern "C"` to keep the C linkage)."""
    lines = ["/* What this file's code calls but doesn't define, declared loosely for the machine drafts "
             "(Ghidra): they call by name. Replace them with real prototypes as you work the functions out. */"]
    if cpp:
        lines += [f'extern "C" unsigned long long {n}(...);' for n in funcs]
        lines += [f'extern "C" unsigned char {n};' for n in data]
    else:
        lines += [f"extern unsigned long long {n}();" for n in funcs]
        lines += [f"extern unsigned char {n};" for n in data]
    return "\n".join(lines) + "\n"


def _headless() -> Path:
    base = toolchains.path("ghidra") / "support"
    return base / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")


def decompile_object(obj: Path, cache_dir: Path, timeout: float = 900) -> dict[str, str]:
    """name -> decompiled C for every function in an object file (cached by the object's content)."""
    data = obj.read_bytes()
    key = hashlib.sha1(data).hexdigest()[:16]
    cache = cache_dir / f"{obj.stem}-{key}.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if not available():
        return {}
    with tempfile.TemporaryDirectory(prefix="decompwtf-ghidra-") as tmp:
        scripts = Path(tmp) / "scripts"
        scripts.mkdir()
        src = resources.files("decompnet.forks").joinpath("ghidra_scripts", "DecompWtfExport.java")
        (scripts / "DecompWtfExport.java").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        out = Path(tmp) / "out.jsonl"
        target = Path(tmp) / obj.name
        shutil.copyfile(obj, target)
        argv = [str(_headless()), tmp, "decompwtf", "-import", str(target), "-scriptPath", str(scripts),
                "-postScript", "DecompWtfExport.java", str(out), "-deleteProject"]
        try:
            subprocess.run(capped(argv), capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return {}
        result = {}
        if out.exists():
            for line in out.read_text(encoding="utf-8").splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                result[row["name"]] = row["c"]
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(result), encoding="utf-8")
    return result
