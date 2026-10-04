"""Raw-byte parser for little-endian x86-64 ELF64 ET_REL relocatable objects.

Only the subset needed for link-time symbol arbitration is decoded:
ELF header, section headers and the (link, info) relationship between
.symtab / .strtab / .shstrtab.  Nothing is executed and no section data
is interpreted as code.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ELFMAG = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_REL = 1
EM_X86_64 = 62
EV_CURRENT = 1

SHT_SYMTAB = 2
SHT_STRTAB = 3

SHF_COMPRESSED = 0x800

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_SECTION = 3

SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
SHN_XINDEX = 0xFFFF

# ELF64 header is 64 bytes; section header entry is 64 bytes; symbol entry 24.
EHDR_SIZE = 64
SHDR_SIZE = 64
SYM_SIZE = 24


class ELFError(ValueError):
    """Raised when a byte stream is not a valid x86-64 ELF64 ET_REL object."""


@dataclass(frozen=True)
class Symbol:
    name: str
    binding: int  # STB_LOCAL / STB_GLOBAL / STB_WEAK
    type: int
    shndx: int
    defined: bool

    @property
    def strong(self) -> bool:
        return self.defined and self.binding == STB_GLOBAL

    @property
    def weak(self) -> bool:
        return self.binding == STB_WEAK

    @property
    def label(self) -> str:
        if not self.defined:
            return "undefined"
        if self.binding == STB_GLOBAL:
            return "strong"
        if self.binding == STB_WEAK:
            return "weak"
        return "local"


@dataclass(frozen=True)
class ELFObject:
    symbols: list[Symbol]

    def global_strong_defs(self) -> dict[str, Symbol]:
        return {s.name: s for s in self.symbols if s.strong}

    def global_weak_defs(self) -> dict[str, Symbol]:
        return {s.name: s for s in self.symbols if s.defined and s.weak}

    def undefined_refs(self) -> dict[str, Symbol]:
        return {s.name: s for s in self.symbols if not s.defined}


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _read_cstr(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        raise ELFError("string table index out of bounds")
    end = buf.find(b"\x00", off)
    if end < 0:
        raise ELFError("unterminated string table entry")
    try:
        return buf[off:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ELFError("symbol name is not valid UTF-8") from exc


@dataclass(frozen=True)
class _Section:
    name_off: int
    sh_type: int
    sh_flags: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_entsize: int


def _sections(buf: bytes) -> list[_Section]:
    shoff = _u64(buf, 40)
    shentsize = _u16(buf, 58)
    shnum = _u16(buf, 60)
    shstrndx = _u16(buf, 62)

    if shentsize != SHDR_SIZE:
        raise ELFError(f"unsupported section header entry size {shentsize}")
    if shnum == 0:
        raise ELFError("object has no sections")
    if shoff == 0 or shoff + shnum * SHDR_SIZE > len(buf):
        raise ELFError("section header table overruns file")
    if shstrndx >= shnum:
        raise ELFError("invalid section name string table index")

    out: list[_Section] = []
    for i in range(shnum):
        base = shoff + i * SHDR_SIZE
        sec = _Section(
            name_off=_u32(buf, base),
            sh_type=_u32(buf, base + 4),
            sh_flags=_u64(buf, base + 8),
            sh_offset=_u64(buf, base + 24),
            sh_size=_u64(buf, base + 32),
            sh_link=_u32(buf, base + 40),
            sh_entsize=_u64(buf, base + 56),
        )
        if sec.sh_flags & SHF_COMPRESSED:
            raise ELFError(
                f"section {i} is compressed (SHF_COMPRESSED); only "
                "uncompressed members are accepted"
            )
        # SHT_NOBITS would be legal in a relocatable but offsets must still
        # be sane for every other type; check the concrete ranges lazily.
        if sec.sh_type != 8:  # != SHT_NOBITS
            if sec.sh_offset > len(buf) or sec.sh_offset + sec.sh_size > len(buf):
                raise ELFError(f"section {i} data overruns file")
        out.append(sec)
    return out


def parse_elf(buf: bytes) -> ELFObject:
    """Validate raw bytes and extract externally visible symbol information."""
    if len(buf) < EHDR_SIZE:
        raise ELFError("file shorter than ELF64 header")
    if buf[:4] != ELFMAG:
        raise ELFError("bad ELF magic")
    if buf[4] != ELFCLASS64:
        raise ELFError("only ELFCLASS64 is supported")
    if buf[5] != ELFDATA2LSB:
        raise ELFError("only little-endian objects are supported")
    if buf[6] != EV_CURRENT:
        raise ELFError(f"unsupported ELF version {buf[6]}")
    if buf[7] != 0:  # EI_OSABI must be System V for our narrow target
        raise ELFError(f"unsupported OS/ABI {buf[7]}")

    e_type = _u16(buf, 16)
    if e_type != ET_REL:
        kind = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}.get(e_type, e_type)
        raise ELFError(f"only ET_REL objects are accepted, got {kind}")
    if _u16(buf, 18) != EM_X86_64:
        raise ELFError("only x86-64 objects are accepted")
    if _u32(buf, 20) != EV_CURRENT:
        raise ELFError("bad e_ident/e_version combination")
    if _u32(buf, 48) != 0:  # e_flags must be zero for x86-64
        raise ELFError("non-zero e_flags")

    sections = _sections(buf)

    symtabs = [s for s in sections if s.sh_type == SHT_SYMTAB]
    if not symtabs:
        raise ELFError("object has no symbol table")

    symbols: list[Symbol] = []
    for idx, st in enumerate(symtabs):
        if st.sh_link >= len(sections):
            raise ELFError("symbol table link does not point at a string table")
        strtab = sections[st.sh_link]
        if strtab.sh_type != SHT_STRTAB:
            raise ELFError("symbol table link does not point at SHT_STRTAB")
        strbuf = buf[strtab.sh_offset : strtab.sh_offset + strtab.sh_size]

        entsize = st.sh_entsize or SYM_SIZE
        if entsize != SYM_SIZE:
            raise ELFError(f"unsupported Elf64_Sym entry size {entsize}")
        if st.sh_size == 0 or st.sh_size % SYM_SIZE:
            raise ELFError("symbol table size is not a whole number of entries")

        count = st.sh_size // SYM_SIZE
        if count < 1:
            raise ELFError("symbol table missing null entry")
        # First entry must be the reserved null symbol.
        first = buf[st.sh_offset : st.sh_offset + SYM_SIZE]
        if first != b"\x00" * SYM_SIZE:
            raise ELFError("symbol table missing leading null symbol")

        # st_info: lower 4 bits type, upper 4 binding.
        for n in range(1, count):
            base = st.sh_offset + n * SYM_SIZE
            st_name = _u32(buf, base)
            st_info = buf[base + 4]
            st_shndx = _u16(buf, base + 6)
            binding = st_info >> 4
            stype = st_info & 0x0F
            name = _read_cstr(strbuf, st_name)

            if st_shndx == SHN_XINDEX:
                raise ELFError("extended section indices (SHN_XINDEX) are not supported")
            if st_shndx >= len(sections) and st_shndx not in (
                SHN_UNDEF,
                SHN_ABS,
                SHN_COMMON,
            ):
                raise ELFError(f"symbol {name!r} references invalid section index")

            if binding == STB_LOCAL:
                # Locals never participate in cross-object arbitration.
                continue
            if binding not in (STB_GLOBAL, STB_WEAK):
                # GNU-specific bindings (GNU_UNIQUE etc.) are out of scope.
                raise ELFError(
                    f"symbol {name!r} has unsupported binding {binding}"
                )

            if stype == STT_SECTION:
                # Section symbols are compiler-generated and never named links.
                continue

            if not name:
                # An external (global/weak) symbol with st_name == 0 is
                # malformed: it can neither be arbitrated nor linked.
                raise ELFError("external symbol has an empty name")

            defined = st_shndx != SHN_UNDEF
            symbols.append(
                Symbol(
                    name=name,
                    binding=binding,
                    type=stype,
                    shndx=st_shndx,
                    defined=defined,
                )
            )

    return ELFObject(symbols=symbols)
