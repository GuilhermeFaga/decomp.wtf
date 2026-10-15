"""What a COFF object's code calls but doesn't define: the names, read back out of its symbol table.

Unity's targets are COFF (Windows x86-64): il2cppsplits writes them, and for every call or data reference
records the symbol the compiler would have written — defined functions live in .text, everything else is
either an undefined function (type 0x20, section 0) or a data symbol (absolute, the target RVA as value).
Autopilot reads those back to declare a unit's externals before it tries a machine draft that calls them.
"""

from __future__ import annotations

import struct
from pathlib import Path

SYM_UNDEFINED = 0
SYM_ABSOLUTE = -1
STYPE_FUNCTION = 0x20
CLASS_EXTERNAL = 2
CLASS_STATIC = 3


def externals(path: Path) -> tuple[list[str], list[str]]:
    """(functions, data) the object refers to without defining, in symbol-table order. ([], []) when the file
    isn't a COFF object (ELF, Mach-O) or has no symbol table."""
    try:
        d = path.read_bytes()
    except OSError:
        return [], []
    if len(d) < 20 or d[:4] == b"\x7fELF":
        return [], []
    symoff, nsym = struct.unpack_from("<II", d, 8)
    if not symoff or not nsym or symoff + 18 * nsym > len(d):
        return [], []
    strtab = d[symoff + 18 * nsym:]
    funcs: list[str] = []
    data: list[str] = []
    i = 0
    while i < nsym:
        o = symoff + 18 * i
        head = d[o:o + 8]
        if head[:4] == b"\0\0\0\0":  # a long name: an offset into the string table that follows the symbols
            at, = struct.unpack_from("<I", head, 4)
            end = strtab.find(b"\0", at)
            name = strtab[at:end].decode(errors="replace") if 4 <= at < len(strtab) and end > at else ""
        else:
            name = head.rstrip(b"\0").decode(errors="replace")
        _, section = struct.unpack_from("<Ih", d, o + 8)
        stype, storage, naux = struct.unpack_from("<HBB", d, o + 14)
        if name and not name.startswith(".") and storage in (CLASS_EXTERNAL, CLASS_STATIC):
            if section == SYM_UNDEFINED and stype & STYPE_FUNCTION:
                funcs.append(name)
            elif section in (SYM_UNDEFINED, SYM_ABSOLUTE) and not stype & STYPE_FUNCTION:
                data.append(name)
        i += 1 + naux
    return funcs, data
