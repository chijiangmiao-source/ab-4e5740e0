"""Raw-byte fixtures synthesizing little-endian x86-64 ELF64 ET_REL
objects and GNU ar archives, with precise control over symbols.

The host toolchain in CI may target another architecture, so fixtures are
emitted byte-by-byte rather than produced by gcc/ar; they are byte-identical
in shape to what GNU binutils writes for the same inputs.
"""

from __future__ import annotations

import struct

STB_LOCAL, STB_GLOBAL, STB_WEAK = 0, 1, 2
STT_NOTYPE, STT_OBJECT, STT_FUNC = 0, 1, 2
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 1, 2, 3


def _cstr_table(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for s in strings:
        if s in offsets:
            continue
        offsets[s] = len(blob)
        blob += s.encode("utf-8") + b"\x00"
    return bytes(blob), offsets


def make_elf_object(specs: list[tuple[str, str]]) -> bytes:
    """Build an ELF64 ET_REL x86-64 object.

    specs entries are (name, kind), kind in:
      strong | weak | common | undef | weak_undef | local_def
    """
    text = b"\xc3"  # one RET byte so definitions have a real section target
    sym_names = [s[0] for s in specs if s[0]]
    strtab, str_off = _cstr_table(sym_names)
    shstr, sh_off = _cstr_table([".text", ".symtab", ".strtab", ".shstrtab"])

    n_local = 1 + sum(1 for _, k in specs if k == "local_def")

    def entry(name: str, bind: int, stype: int, shndx: int, value: int = 0) -> bytes:
        return struct.pack(
            "<IBBHQQ", str_off.get(name, 0), (bind << 4) | stype, 0,
            shndx, value, 0,
        )

    sym = bytearray(b"\x00" * 24)  # mandatory null symbol
    ordered = [s for s in specs if s[1] == "local_def"] + [
        s for s in specs if s[1] != "local_def"
    ]
    for name, kind in ordered:
        if kind == "strong":
            sym += entry(name, STB_GLOBAL, STT_FUNC, 1)
        elif kind == "weak":
            sym += entry(name, STB_WEAK, STT_FUNC, 1)
        elif kind == "common":
            sym += entry(name, STB_GLOBAL, STT_OBJECT, SHN_COMMON, value=8)
        elif kind == "undef":
            sym += entry(name, STB_GLOBAL, STT_NOTYPE, SHN_UNDEF)
        elif kind == "weak_undef":
            sym += entry(name, STB_WEAK, STT_NOTYPE, SHN_UNDEF)
        elif kind == "local_def":
            sym += entry(name, STB_LOCAL, STT_FUNC, 1)
        else:
            raise ValueError(f"unknown symbol kind {kind}")

    off_text = 64
    off_sym = off_text + len(text)
    off_str = off_sym + len(sym)
    off_shstr = off_str + len(strtab)
    shoff = off_shstr + len(shstr)

    def shdr(name: str, sh_type: int, flags: int, offset: int, size: int,
             link: int = 0, info: int = 0, addralign: int = 1,
             entsize: int = 0) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ", sh_off.get(name, 0), sh_type, flags, 0,
            offset, size, link, info, addralign, entsize,
        )

    shdrs = b"\x00" * 64
    shdrs += shdr(".text", SHT_PROGBITS, 0x6, off_text, len(text), addralign=16)
    shdrs += shdr(".symtab", SHT_SYMTAB, 0, off_sym, len(sym),
                  link=3, info=n_local, addralign=8, entsize=24)
    shdrs += shdr(".strtab", SHT_STRTAB, 0, off_str, len(strtab))
    shdrs += shdr(".shstrtab", SHT_STRTAB, 0, off_shstr, len(shstr))

    ehdr = struct.pack(
        "<4s5B7xHHIQQQIHHHHHH",
        b"\x7fELF",
        2, 1, 1, 0, 0,
        1,     # e_type ET_REL
        62,    # e_machine EM_X86_64
        1,     # e_version
        0, 0, shoff, 0,
        64,
        0, 0,
        64, 5, 4,
    )
    return ehdr + text + bytes(sym) + strtab + shstr + shdrs


def patch_elf(buf: bytes, **fields: int) -> bytes:
    """Return a copy with selected ELF header fields corrupted."""
    out = bytearray(buf)
    layout = {
        "ei_class": (4, "B"), "ei_data": (5, "B"), "ei_version": (6, "B"),
        "ei_osabi": (7, "B"), "e_type": (16, "<H"), "e_machine": (18, "<H"),
        "e_version": (20, "<I"), "e_flags": (48, "<I"),
        "e_shoff": (40, "<Q"), "e_shentsize": (58, "<H"),
        "e_shnum": (60, "<H"), "e_shstrndx": (62, "<H"),
    }
    for key, value in fields.items():
        off, fmt = layout[key]
        struct.pack_into(fmt, out, off, value)
    return bytes(out)


def _ar_header(name: bytes, size: int) -> bytes:
    def field(value: bytes, width: int) -> bytes:
        if len(value) > width:
            raise ValueError("ar header field too long")
        return value + b" " * (width - len(value))

    return b"".join(
        [
            field(name, 16),
            field(b"0", 12),
            field(b"0", 6),
            field(b"0", 6),
            field(b"100644", 8),
            field(str(size).encode(), 10),
            b"`\n",
        ]
    )


def make_archive(
    members: list[tuple[str, bytes]],
    index: list[tuple[str, str]] | None = None,
    *,
    wide_index: bool = False,
    long_names: bool = False,
    emit_index: bool = True,
    index_offset_delta: int = 0,
) -> bytes:
    """Build a GNU ar archive.

    * members: (name, object bytes)
    * index: (symbol, member_name) pairs; defaults to every defined symbol.
      Arbitrary names are permitted so tests can forge a corrupt index that
      claims definitions the member does not actually provide.
    * wide_index emits /SYM64 (64-bit big-endian fields)
    * long_names stores member names in the // table (BSD/GNU long name style)
    * emit_index=False omits the symbol index (parser must reject)
    * index_offset_delta shifts every recorded member offset (must be rejected
      as a corrupt index pointing at non-header bytes)
    """
    if index is None:
        from app.elf import parse_elf

        index = []
        seen: set[str] = set()
        for n, blob in members:
            for s in parse_elf(blob).symbols:
                if s.defined and s.name not in seen:
                    seen.add(s.name)
                    index.append((s.name, n))

    out = bytearray(b"!<arch>\n")

    name_table = b""
    name_refs: dict[str, bytes] = {}
    if long_names:
        nt = bytearray()
        for n, _ in members:
            name_refs[n] = b"/" + str(len(nt)).encode()
            nt += n.encode() + b"/\n"
        name_table = bytes(nt)

    def member_header_bytes(name: str, size: int) -> bytes:
        if long_names:
            return _ar_header(name_refs[name], size)
        return _ar_header(name.encode() + b"/", size)

    index_names_blob = b"".join(sym.encode() + b"\x00" for sym, _ in index)
    width = 8 if wide_index else 4
    index_size = width + width * len(index) + len(index_names_blob)
    index_total = len(_ar_header(b"/", index_size)) + index_size + (index_size & 1)

    nt_total = 0
    if long_names:
        nt_total = len(_ar_header(b"//", len(name_table))) + len(name_table)
        nt_total += len(name_table) & 1

    cursor = 8 + index_total + nt_total
    offsets: dict[str, int] = {}
    member_chunks: list[bytes] = []
    for name, blob in members:
        offsets[name] = cursor
        member_chunks.append(member_header_bytes(name, len(blob)) + blob)
        cursor += len(member_chunks[-1]) + (len(blob) & 1)

    if emit_index:
        fmt = ">Q" if wide_index else ">I"
        real = bytearray(struct.pack(fmt, len(index)))
        for sym, member_name in index:
            real += struct.pack(fmt, offsets[member_name] + index_offset_delta)
        real += index_names_blob
        assert len(real) == index_size
        out += _ar_header(b"/SYM64/" if wide_index else b"/", len(real))
        out += real
        if len(real) & 1:
            out += b"\n"
    if long_names:
        out += _ar_header(b"//", len(name_table))
        out += name_table
        if len(name_table) & 1:
            out += b"\n"
    for (_, blob), chunk in zip(members, member_chunks):
        out += chunk
        if len(blob) & 1:
            out += b"\n"
    return bytes(out)
