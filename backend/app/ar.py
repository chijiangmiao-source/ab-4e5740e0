"""Raw-byte parser/validator for GNU ``ar`` archives.

Only the classic GNU format used for static libraries is accepted:

* ``!<arch>\\n`` magic (the ``!<thin>`` variant is rejected because its
  members are not stored as contiguous raw bytes);
* 60-byte member headers with the ````\\n`` trailer;
* the ``/`` (or 64-bit ``/SYM64``) symbol index member, whose integer
  fields are always big-endian regardless of host endianness;
* the ``//`` long-name table with ``/offset`` references from headers.

Every regular member is additionally required to be a valid
little-endian x86-64 ELF64 ET_REL object, and every symbol-index entry
must name a symbol actually defined by the member it points at -- a
mismatch is treated as a corrupt index.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .elf import ELFError, ELFObject, parse_elf

AR_MAGIC = b"!<arch>\n"
AR_THIN_MAGIC = b"!<thin>\n"
AR_FMAG = b"`\n"
HDR_SIZE = 60


class ArError(ValueError):
    """Raised when a byte stream is not a valid GNU ar archive."""


@dataclass(frozen=True)
class ArMember:
    name: str
    header_offset: int
    data_offset: int
    size: int
    data: bytes
    elf: ELFObject | None = None  # None for special members
    # Symbol names the archive index attributes to this member.
    indexed_symbols: tuple[str, ...] = ()
    index_order: int | None = None  # first position of the member in the index


@dataclass(frozen=True)
class Archive:
    members: list[ArMember]
    # (symbol name, member) in the exact order recorded by the index.
    index: list[tuple[str, ArMember]]
    member_order: list[ArMember] = field(default_factory=list)

    def indexed_members_in_order(self) -> list[tuple[ArMember, tuple[str, ...]]]:
        """Members in first-index-occurrence order with their indexed names."""
        seen: dict[int, ArMember] = {}
        names: dict[int, list[str]] = {}
        for sym, member in self.index:
            if id(member) not in seen:
                seen[id(member)] = member
                names[id(member)] = []
            names[id(member)].append(sym)
        return [(m, tuple(names[id(m)])) for m in seen.values()]


def _ascii_decimal(raw: bytes, field_name: str, octal: bool = False) -> int:
    text = raw.decode("ascii", errors="strict").strip()
    digits = "01234567" if octal else "0123456789"
    if text == "":
        return 0
    if any(c not in digits for c in text):
        raise ArError(f"member header field {field_name!r} is not numeric: {raw!r}")
    return int(text, 8 if octal else 10)


def _resolve_long_name(name_table: bytes | None, offset: int) -> str:
    if name_table is None:
        raise ArError("long-name reference but archive has no // name table")
    if offset < 0 or offset >= len(name_table):
        raise ArError(f"long-name offset {offset} is outside the name table")
    # GNU terminates long names with "/\n"; some producers use NUL.
    end_slash = name_table.find(b"/\n", offset)
    end_nul = name_table.find(b"\x00", offset)
    candidates = [e for e in (end_slash, end_nul) if e >= 0]
    if not candidates:
        raise ArError(f"long-name at offset {offset} is not terminated")
    end = min(candidates)
    raw = name_table[offset:end]
    if not raw:
        raise ArError(f"long-name at offset {offset} is empty")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArError("member name is not valid UTF-8") from exc


def _parse_symbol_index(member: ArMember, wide: bool) -> list[tuple[int, str]]:
    """Return (member header offset, symbol name) pairs from / or /SYM64."""
    data = member.data
    width = 8 if wide else 4
    if len(data) < width:
        raise ArError("symbol index member is too small for its count field")
    count = struct.unpack_from(">Q" if wide else ">I", data, 0)[0]
    offsets_end = width + count * width
    if offsets_end > len(data):
        raise ArError("symbol index offset table overruns member")
    offsets = [
        struct.unpack_from(">Q" if wide else ">I", data, width + i * width)[0]
        for i in range(count)
    ]
    name_blob = data[offsets_end:]
    entries: list[tuple[int, str]] = []
    cursor = 0
    for i, member_off in enumerate(offsets):
        end = name_blob.find(b"\x00", cursor)
        if end < 0:
            raise ArError(f"symbol index entry {i} has an unterminated name")
        try:
            sym = name_blob[cursor:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArError("symbol index entry name is not valid UTF-8") from exc
        if not sym:
            raise ArError(f"symbol index entry {i} has an empty name")
        entries.append((member_off, sym))
        cursor = end + 1
    # Trailing bytes after the last NUL are allowed to be padding only.
    if any(b != 0 for b in name_blob[cursor:]):
        raise ArError("trailing garbage after symbol index names")
    return entries


def parse_ar(buf: bytes) -> Archive:
    if len(buf) < 8:
        raise ArError("data shorter than ar magic")
    if buf[:8] == AR_THIN_MAGIC:
        raise ArError("thin archives are not supported (members are not raw bytes)")
    if buf[:8] != AR_MAGIC:
        raise ArError("bad ar magic")

    members: list[ArMember] = []
    name_table: bytes | None = None
    symbol_index_member: ArMember | None = None
    symbol_index_wide = False

    pos = 8
    ordinal = 0
    regular_seen = False
    while pos < len(buf):
        if pos + HDR_SIZE > len(buf):
            raise ArError(f"truncated member header at archive offset {pos}")
        hdr = buf[pos : pos + HDR_SIZE]
        if hdr[58:60] != AR_FMAG:
            raise ArError(f"bad member header magic at archive offset {pos}")

        name_field = hdr[0:16]
        # Strict validation of the numeric header fields.
        _ascii_decimal(hdr[16:28], "mtime")
        _ascii_decimal(hdr[28:34], "uid")
        _ascii_decimal(hdr[34:40], "gid")
        _ascii_decimal(hdr[40:48], "mode", octal=True)
        size = _ascii_decimal(hdr[48:58], "size")

        data_offset = pos + HDR_SIZE
        data_end = data_offset + size
        if data_end > len(buf):
            raise ArError(
                f"member at archive offset {pos} declares size {size} that overruns "
                "the archive"
            )
        if size & 1:
            if data_end == len(buf) or buf[data_end] != 0x0A:
                raise ArError(
                    f"odd-sized member at archive offset {pos} is missing LF padding"
                )
        next_pos = data_end + (size & 1)

        try:
            field_text = name_field.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ArError("non-ASCII member name field") from exc

        stripped = field_text.strip()
        is_special = False
        if stripped in ("/", "//") or stripped.startswith("/SYM64"):
            is_special = True
            if regular_seen:
                raise ArError(
                    f"special member {stripped!r} must precede regular members"
                )
            if stripped == "//":
                if name_table is not None:
                    raise ArError("duplicate // long-name table")
                name_table = buf[data_offset:data_end]
            elif stripped == "/":
                if symbol_index_member is not None:
                    raise ArError("duplicate / symbol index")
                symbol_index_wide = False
            else:  # /SYM64
                if symbol_index_member is not None:
                    raise ArError("duplicate symbol index (/ and /SYM64)")
                symbol_index_wide = True
        else:
            regular_seen = True

        member = ArMember(
            name="",  # filled below for regular members
            header_offset=pos,
            data_offset=data_offset,
            size=size,
            data=buf[data_offset:data_end],
        )
        if is_special:
            # Keep a placeholder so offsets can be cross-checked later; the
            # symbol-table member gets replaced once we know its entries.
            members.append(member)
            if stripped in ("/",) or stripped.startswith("/SYM64"):
                symbol_index_member = member
        else:
            if stripped.startswith("/") and stripped[1:].isdigit():
                name = _resolve_long_name(name_table, int(stripped[1:]))
            else:
                # GNU writes ordinary names with a trailing slash, e.g. "foo.o/".
                name = stripped.rstrip("/")
                if not name or "/" in name:
                    raise ArError(f"invalid member name field {field_text!r}")
            member = ArMember(
                name=name,
                header_offset=pos,
                data_offset=data_offset,
                size=size,
                data=buf[data_offset:data_end],
            )
            members.append(member)
            ordinal += 1

        pos = next_pos

    if symbol_index_member is None:
        raise ArError("archive has no symbol index member (/ or /SYM64)")

    raw_entries = _parse_symbol_index(symbol_index_member, symbol_index_wide)

    by_offset = {m.header_offset: m for m in members}
    index: list[tuple[str, ArMember]] = []
    seen_index_members: set[int] = set()
    for entry_no, (off, sym) in enumerate(raw_entries):
        target = by_offset.get(off)
        if target is None:
            raise ArError(
                f"symbol index entry {entry_no} ({sym!r}) points at archive "
                f"offset {off}, which is not a member header"
            )
        if target is symbol_index_member or (
            target.data_offset == symbol_index_member.data_offset
        ):
            raise ArError(f"symbol index entry {entry_no} points at the index itself")
        if not target.name:
            raise ArError(
                f"symbol index entry {entry_no} points at the // name table"
            )
        index.append((sym, target))
        seen_index_members.add(id(target))

    # Eagerly validate every regular member at the ar boundary and bind ELF.
    regular_members = [m for m in members if m.name]
    for m in regular_members:
        try:
            elf = parse_elf(m.data)
        except ELFError as exc:
            raise ArError(f"member {m.name!r} is not a valid ELF64 ET_REL: {exc}") from exc
        object.__setattr__(m, "elf", elf)

    # Cross-check the index against the definitions actually present.
    defined_by_member: dict[int, set[str]] = {}
    for m in regular_members:
        defs = {s.name for s in m.elf.symbols if s.defined}
        defined_by_member[id(m)] = defs
    order_rank: dict[int, int] = {}
    for entry_no, (sym, m) in enumerate(index):
        if not sym:
            raise ArError(f"symbol index entry {entry_no} has an empty name")
        if sym not in defined_by_member[id(m)]:
            raise ArError(
                f"corrupt symbol index: entry {entry_no} claims member "
                f"{m.name!r} defines {sym!r}, but it does not"
            )
        if id(m) not in order_rank:
            order_rank[id(m)] = entry_no

    bound_members: list[ArMember] = []
    for m in regular_members:
        idx_names = tuple(sym for sym, mm in index if mm is m)
        bound_members.append(
            ArMember(
                name=m.name,
                header_offset=m.header_offset,
                data_offset=m.data_offset,
                size=m.size,
                data=m.data,
                elf=m.elf,
                indexed_symbols=idx_names,
                index_order=order_rank.get(id(m)),
            )
        )
    bound_by_offset = {m.header_offset: m for m in bound_members}
    bound_index = [(sym, bound_by_offset[mm.header_offset]) for sym, mm in index]

    return Archive(members=bound_members, index=bound_index, member_order=bound_members)
