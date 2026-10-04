"""Parser rule tests: raw-byte validation of ELF64 ET_REL and GNU ar.

Run directly (python -m tests.test_parsers) or through the verify service.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ar import ArError, parse_ar
from app.elf import ELFError, parse_elf

from tests.fixtures import make_archive, make_elf_object, patch_elf


class ELFParserRules(unittest.TestCase):
    def setUp(self) -> None:
        self.obj = make_elf_object(
            [("main", "strong"), ("helper", "weak"),
             ("flag", "common"), ("malloc", "undef"),
             ("optmalloc", "weak_undef"), ("hidden", "local_def")]
        )

    def test_valid_object_symbol_classification(self) -> None:
        parsed = parse_elf(self.obj)
        by_name = {s.name: s for s in parsed.symbols}
        self.assertEqual(set(by_name), {"main", "helper", "flag", "malloc", "optmalloc"})
        self.assertTrue(by_name["main"].strong)
        self.assertEqual(by_name["helper"].label, "weak")
        self.assertTrue(by_name["flag"].defined)
        self.assertEqual(by_name["flag"].shndx, 0xFFF2)
        self.assertEqual(by_name["malloc"].label, "undefined")
        self.assertEqual(by_name["optmalloc"].label, "undefined")
        self.assertTrue(by_name["optmalloc"].weak)

    def test_bad_magic(self) -> None:
        with self.assertRaisesRegex(ELFError, "magic"):
            parse_elf(b"not an elf file at all" + b"\x00" * 80)

    def test_truncated_header(self) -> None:
        with self.assertRaisesRegex(ELFError, "shorter than ELF64 header"):
            parse_elf(self.obj[:40])

    def test_wrong_class(self) -> None:
        with self.assertRaisesRegex(ELFError, "ELFCLASS64"):
            parse_elf(patch_elf(self.obj, ei_class=1))

    def test_big_endian_rejected(self) -> None:
        with self.assertRaisesRegex(ELFError, "little-endian"):
            parse_elf(patch_elf(self.obj, ei_data=2))

    def test_non_rel_rejected(self) -> None:
        with self.assertRaisesRegex(ELFError, "ET_REL"):
            parse_elf(patch_elf(self.obj, e_type=2))

    def test_non_x86_64_rejected(self) -> None:
        with self.assertRaisesRegex(ELFError, "x86-64"):
            parse_elf(patch_elf(self.obj, e_machine=183))  # EM_AARCH64

    def test_bad_version_and_flags(self) -> None:
        with self.assertRaisesRegex(ELFError, "version"):
            parse_elf(patch_elf(self.obj, ei_version=0))
        with self.assertRaisesRegex(ELFError, "e_flags"):
            parse_elf(patch_elf(self.obj, e_flags=1))

    def test_section_table_overrun(self) -> None:
        with self.assertRaisesRegex(ELFError, "section header table overruns"):
            parse_elf(patch_elf(self.obj, e_shoff=len(self.obj) - 8))

    def test_bad_shnum(self) -> None:
        with self.assertRaisesRegex(ELFError, "no sections"):
            parse_elf(patch_elf(self.obj, e_shnum=0))

    def test_bad_shstrndx(self) -> None:
        with self.assertRaisesRegex(ELFError, "section name string table"):
            parse_elf(patch_elf(self.obj, e_shstrndx=99))

    def test_compressed_section_rejected(self) -> None:
        broken = bytearray(self.obj)
        # Set SHF_COMPRESSED (0x800) on .text = section header index 1.
        import struct

        shoff = struct.unpack_from("<Q", broken, 40)[0]
        flags_off = shoff + 1 * 64 + 8
        flags = struct.unpack_from("<Q", broken, flags_off)[0] | 0x800
        struct.pack_into("<Q", broken, flags_off, flags)
        with self.assertRaisesRegex(ELFError, "compressed"):
            parse_elf(bytes(broken))

    def test_symbol_table_size_misaligned(self) -> None:
        # Shrink the declared .symtab size by one byte: not whole entries.
        broken = bytearray(self.obj)
        sym_shdr_off = int.from_bytes(broken[40:48], "little") + 2 * 64
        broken[sym_shdr_off + 32 : sym_shdr_off + 40] = (
            (int.from_bytes(broken[sym_shdr_off + 32 : sym_shdr_off + 40], "little") - 1).to_bytes(8, "little")
        )
        with self.assertRaisesRegex(ELFError, "whole number of entries"):
            parse_elf(bytes(broken))


class ArParserRules(unittest.TestCase):
    def setUp(self) -> None:
        self.a_o = make_elf_object([("alpha", "strong"), ("beta", "undef")])
        self.b_o = make_elf_object([("beta", "strong")])
        self.arc = make_archive([("alpha.o", self.a_o), ("beta.o", self.b_o)])

    def test_valid_short_names(self) -> None:
        a = parse_ar(self.arc)
        self.assertEqual([m.name for m in a.member_order], ["alpha.o", "beta.o"])
        index = {sym: m.name for sym, m in a.index}
        self.assertEqual(index["alpha"], "alpha.o")
        self.assertEqual(index["beta"], "beta.o")
        self.assertEqual(a.members[0].indexed_symbols, ("alpha",))

    def test_long_name_table(self) -> None:
        long_name = "a-rather-long-member-name-that-exceeds-15-chars.o"
        blob = make_archive([(long_name, self.a_o)], long_names=True)
        a = parse_ar(blob)
        self.assertEqual(a.member_order[0].name, long_name)

    def test_wide_64bit_symbol_index(self) -> None:
        blob = make_archive([("alpha.o", self.a_o)], wide_index=True)
        a = parse_ar(blob)
        self.assertEqual([s for s, _ in a.index], ["alpha"])

    def test_missing_symbol_index_rejected(self) -> None:
        blob = make_archive([("alpha.o", self.a_o)], emit_index=False)
        with self.assertRaisesRegex(ArError, "no symbol index"):
            parse_ar(blob)

    def test_thin_archive_rejected(self) -> None:
        with self.assertRaisesRegex(ArError, "[Tt]hin"):
            parse_ar(b"!<thin>\n" + self.arc[8:])

    def test_bad_magic(self) -> None:
        with self.assertRaisesRegex(ArError, "bad ar magic"):
            parse_ar(b"!<bogus>\n" + b"\x00" * 80)

    def test_bad_member_header_marker(self) -> None:
        broken = bytearray(self.arc)
        # 8 (magic) + 60 (index hdr) + index body ... corrupt first member
        # header: locate second 60-byte header via the index offset table.
        import struct

        count = struct.unpack_from(">I", self.arc, 8 + 60)[0]
        first_member = struct.unpack_from(">I", self.arc, 8 + 64)[0]
        self.assertEqual(count, 2)
        broken[first_member + 58] = ord("x")
        with self.assertRaisesRegex(ArError, "bad member header magic"):
            parse_ar(bytes(broken))

    def test_member_size_overrun_rejected(self) -> None:
        broken = bytearray(self.arc)
        # Inflate the size field of the first member header by 10.
        import struct

        first_member = struct.unpack_from(">I", self.arc, 8 + 64)[0]
        size_off = first_member + 48
        size = int(bytes(broken[size_off : size_off + 10]).strip())
        broken[size_off : size_off + 10] = f"{size + len(self.arc) + 100:<10}".encode()
        with self.assertRaisesRegex(ArError, "overruns"):
            parse_ar(bytes(broken))

    def test_index_offset_points_at_non_header(self) -> None:
        blob = make_archive(
            [("alpha.o", self.a_o)], index_offset_delta=4
        )
        with self.assertRaisesRegex(ArError, "not a member header"):
            parse_ar(blob)

    def test_index_claims_undefined_symbol_is_defined(self) -> None:
        # Forge an index claiming alpha.o exports "beta", which it only refs.
        blob = make_archive(
            [("alpha.o", self.a_o), ("beta.o", self.b_o)],
            index=[("alpha", "alpha.o"), ("beta", "alpha.o")],
        )
        with self.assertRaisesRegex(ArError, "corrupt symbol index"):
            parse_ar(blob)

    def test_index_claims_phantom_symbol(self) -> None:
        blob = make_archive(
            [("alpha.o", self.a_o)], index=[("phantom", "alpha.o")]
        )
        with self.assertRaisesRegex(ArError, "corrupt symbol index"):
            parse_ar(blob)

    def test_member_that_is_not_elf_rejected(self) -> None:
        blob = make_archive(
            [("alpha.o", self.a_o)],  # valid member for index building
        )
        # Replace the member data bytes with garbage, keeping size: simplest
        # is to append a fresh archive whose member data is garbage but whose
        # index claims nothing about it; remove index entries instead.
        import struct

        # Build by hand: archive with index count 0 + one garbage member.
        hdr = lambda name, size: (
            name.ljust(16).encode() + b"0".ljust(12) + b"0".ljust(6)
            + b"0".ljust(6) + b"100644".ljust(8) + str(size).encode().ljust(10)
            + b"`\n"
        )
        idx = struct.pack(">I", 0)
        garbage = b"this is definitely not an elf object"
        out = b"!<arch>\n" + hdr("/", len(idx)) + idx
        if len(idx) & 1:
            out += b"\n"
        out += hdr("junk.o/", len(garbage)) + garbage
        with self.assertRaisesRegex(ArError, "not a valid ELF64 ET_REL"):
            parse_ar(out)

    def test_duplicate_long_name_table_rejected(self) -> None:
        blob = make_archive(
            [("a-rather-long-member-name-that-exceeds-15-chars.o", self.a_o)],
            long_names=True,
        )
        marker = b"//" + b" " * 14
        nt_hdr_pos = blob.find(marker)
        self.assertGreater(nt_hdr_pos, 0)
        # The name-table header declares the table size; duplicate both the
        # 60-byte header and its payload right before the genuine one.
        import struct

        nt_size = int(bytes(blob[nt_hdr_pos + 48 : nt_hdr_pos + 58]).strip())
        duplicate = blob[nt_hdr_pos : nt_hdr_pos + 60 + nt_size + (nt_size & 1)]
        broken = blob[:nt_hdr_pos] + duplicate + blob[nt_hdr_pos:]
        with self.assertRaisesRegex(ArError, "duplicate // long-name table"):
            parse_ar(broken)


if __name__ == "__main__":
    unittest.main(verbosity=2)
