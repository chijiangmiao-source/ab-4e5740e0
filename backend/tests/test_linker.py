"""Link-arbitration rule tests: left-to-right semantics, archives, groups."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ar import parse_ar
from app.elf import parse_elf
from app.linker import Engine, InputItem, LinkRejected

from tests.fixtures import make_archive, make_elf_object


def build_engine(specs: list[tuple]) -> Engine:
    """specs: (kind, name, payload, grouped) where kind is obj/arc and
    payload is a symbol spec list (obj) or a list of (member, symspecs)."""
    items: list[InputItem] = []
    for i, (kind, name, payload, grouped) in enumerate(specs, start=1):
        if kind == "obj":
            blob = make_elf_object(payload)
            items.append(InputItem(i, name, grouped, "object", obj=parse_elf(blob)))
        elif kind == "arc":
            members = [(mname, make_elf_object(mspecs)) for mname, mspecs in payload]
            blob = make_archive(members)
            items.append(
                InputItem(i, name, grouped, "archive", archive=parse_ar(blob))
            )
        else:
            raise ValueError(kind)
    return Engine(items)


def run(specs) -> dict:
    return build_engine(specs).run()


class ObjectLinking(unittest.TestCase):
    def test_simple_left_to_right_objects(self) -> None:
        r = run([
            ("obj", "main.o", [("main", "strong"), ("a", "undef")], False),
            ("obj", "a.o", [("a", "strong")], False),
        ])
        self.assertEqual(r["status"], "accepted")
        self.assertIn("main", r["defined_symbols"])
        self.assertIn("a", r["defined_symbols"])

    def test_definition_before_reference_still_resolves(self) -> None:
        r = run([
            ("obj", "a.o", [("a", "strong")], False),
            ("obj", "main.o", [("main", "strong"), ("a", "undef")], False),
        ])
        self.assertEqual(r["status"], "accepted")

    def test_undefined_at_end_rejected_with_evidence(self) -> None:
        eng = build_engine([
            ("obj", "main.o", [("main", "strong"), ("missing", "undef")], False),
        ])
        with self.assertRaises(LinkRejected) as cm:
            eng.run()
        payload = cm.exception.payload
        self.assertEqual(payload["detail"]["rule"], "undefined_at_close")
        self.assertEqual(payload["symbol"], "missing")
        self.assertEqual(payload["undefined_at_failure"], ["missing"])
        self.assertEqual(payload["location"]["item_index"], 1)
        self.assertEqual(payload["detail"]["all_undefined"], ["missing"])
        # Reference site evidence points at the first referrer.
        self.assertEqual(
            payload["detail"]["reference_sites"]["missing"][0]["item_name"], "main.o"
        )

    def test_duplicate_strong_definition_rejected_at_second_site(self) -> None:
        eng = build_engine([
            ("obj", "a1.o", [("a", "strong")], False),
            ("obj", "a2.o", [("a", "strong")], False),
        ])
        with self.assertRaises(LinkRejected) as cm:
            eng.run()
        p = cm.exception.payload
        self.assertEqual(p["detail"]["rule"], "duplicate_strong_definition")
        self.assertEqual(p["symbol"], "a")
        self.assertEqual(p["location"]["item_index"], 2)
        self.assertEqual(p["location"]["item_name"], "a2.o")
        self.assertEqual(
            p["detail"]["existing_provider"]["location"]["item_name"], "a1.o"
        )

    def test_weak_then_strong_supersedes_without_error(self) -> None:
        r = run([
            ("obj", "w.o", [("a", "weak")], False),
            ("obj", "s.o", [("a", "strong")], False),
        ])
        self.assertEqual(r["status"], "accepted")
        sup = [d for d in r["decisions"] if d["type"] == "supersede"]
        self.assertEqual(len(sup), 1)
        self.assertEqual(sup[0]["chosen"]["location"]["item_name"], "s.o")

    def test_strong_then_weak_keeps_first_silently_recorded(self) -> None:
        r = run([
            ("obj", "s.o", [("a", "strong")], False),
            ("obj", "w.o", [("a", "weak")], False),
        ])
        self.assertEqual(r["status"], "accepted")
        ignored = [d for d in r["decisions"] if d["type"] == "ignore_later_definition"]
        self.assertEqual(len(ignored), 1)
        self.assertEqual(ignored[0]["chosen"]["location"]["item_name"], "s.o")

    def test_two_weak_definitions_first_wins(self) -> None:
        r = run([
            ("obj", "w1.o", [("a", "weak")], False),
            ("obj", "w2.o", [("a", "weak")], False),
        ])
        self.assertEqual(r["status"], "accepted")
        d = [x for x in r["decisions"] if x["symbol"] == "a"]
        self.assertEqual(d[0]["rule"], "equal_strength_first_wins")

    def test_common_yields_to_later_strong(self) -> None:
        r = run([
            ("obj", "c.o", [("a", "common")], False),
            ("obj", "s.o", [("a", "strong")], False),
        ])
        self.assertEqual(r["status"], "accepted")
        self.assertTrue(any(d["type"] == "supersede" for d in r["decisions"]))

    def test_common_supersedes_weak_in_both_orders(self) -> None:
        # GNU ld: tentative COMMON beats a defined weak symbol regardless of
        # command order (strong > COMMON > weak).
        for order in (("weak", "common"), ("common", "weak")):
            specs = [
                ("obj", "w.o", [("a", "weak")], False)
                if order[0] == "weak"
                else ("obj", "c.o", [("a", "common")], False),
                ("obj", "w2.o", [("a", "weak")], False)
                if order[1] == "weak"
                else ("obj", "c2.o", [("a", "common")], False),
            ]
            r = run(specs)
            self.assertEqual(r["status"], "accepted", order)
            chosen = [d for d in r["decisions"] if d["type"] in ("supersede", "ignore_later_definition")]
            weak_first = order[0] == "weak"
            if weak_first:
                self.assertTrue(
                    any(d["type"] == "supersede" and d["chosen"]["strength"] == "common"
                        for d in chosen),
                    order,
                )
            else:
                self.assertTrue(
                    any(d["type"] == "ignore_later_definition"
                        and d["chosen"]["strength"] == "common"
                        for d in chosen),
                    order,
                )

    def test_strong_before_common_keeps_strong(self) -> None:
        r = run([
            ("obj", "s.o", [("a", "strong")], False),
            ("obj", "c.o", [("a", "common")], False),
        ])
        self.assertEqual(r["status"], "accepted")

    def test_weak_undefined_does_not_fail_link(self) -> None:
        r = run([
            ("obj", "main.o",
             [("main", "strong"), ("opt", "weak_undef")], False),
        ])
        self.assertEqual(r["status"], "accepted")
        self.assertEqual(r["weak_unresolved"][0]["symbol"], "opt")

    def test_weak_reference_does_not_pull_archive_member(self) -> None:
        r = run([
            ("obj", "main.o", [("main", "strong"), ("a", "weak_undef")], False),
            ("arc", "lib.a", [("a.o", [("a", "strong")])], False),
        ])
        self.assertEqual(r["status"], "accepted")
        self.assertEqual(r["extraction_order"], [])
        self.assertEqual(
            [w["symbol"] for w in r["weak_unresolved"]], ["a"]
        )

    def test_strong_after_weak_reference_pulls_member(self) -> None:
        # A weak-only ref passes the archive without extraction; a later
        # object upgrades it to a strong ref -- but the archive is already
        # gone, so the link must fail (classic archive ordering evidence).
        eng = build_engine([
            ("obj", "wmain.o", [("main", "strong"), ("a", "weak_undef")], False),
            ("arc", "lib.a", [("a.o", [("a", "strong")])], False),
            ("obj", "late.o", [("late", "strong"), ("a", "undef")], False),
        ])
        with self.assertRaises(LinkRejected) as cm:
            eng.run()
        self.assertEqual(cm.exception.payload["undefined_at_failure"], ["a"])
        self.assertEqual(cm.exception.payload["extraction_order"], [])


class ArchiveSemantics(unittest.TestCase):
    def test_archive_extracts_for_prior_undefined(self) -> None:
        r = run([
            ("obj", "main.o", [("main", "strong"), ("a", "undef")], False),
            ("arc", "lib.a", [("a.o", [("a", "strong")])], False),
        ])
        self.assertEqual(r["status"], "accepted")
        self.assertEqual(len(r["extraction_order"]), 1)
        e = r["extraction_order"][0]
        self.assertEqual(e["member"], "a.o")
        self.assertEqual(e["triggered_by"], ["a"])

    def test_archive_before_reference_extracts_nothing_and_fails(self) -> None:
        eng = build_engine([
            ("arc", "lib.a", [("a.o", [("a", "strong")])], False),
            ("obj", "main.o", [("main", "strong"), ("a", "undef")], False),
        ])
        with self.assertRaises(LinkRejected) as cm:
            eng.run()
        self.assertEqual(cm.exception.payload["detail"]["rule"], "undefined_at_close")
        self.assertEqual(cm.exception.payload["extraction_order"], [])

    def test_archive_member_not_pulled_without_need(self) -> None:
        r = run([
            ("obj", "main.o", [("main", "strong"), ("a", "undef")], False),
            ("arc", "lib.a",
             [("a.o", [("a", "strong")]), ("b.o", [("b", "strong")])], False),
        ])
        self.assertEqual([e["member"] for e in r["extraction_order"]], ["a.o"])

    def test_archive_internal_cascade(self) -> None:
        # a (needed) references b in a later member of the same archive.
        r = run([
            ("obj", "main.o", [("main", "strong"), ("a", "undef")], False),
            ("arc", "lib.a",
             [("a.o", [("a", "strong"), ("b", "undef")]),
              ("b.o", [("b", "strong")])], False),
        ])
        self.assertEqual(r["status"], "accepted")
        self.assertEqual(
            [e["member"] for e in r["extraction_order"]], ["a.o", "b.o"]
        )
        # Evidence of the archive's own internal rounds.
        arc_rounds = [x for x in r["rounds"] if x["scope"] == "archive"]
        self.assertGreaterEqual(len(arc_rounds), 2)

    def test_archive_member_satisfying_creates_no_strong_clash(self) -> None:
        r = run([
            ("obj", "main.o", [("main", "strong"), ("a", "undef")], False),
            ("arc", "lib.a",
             [("a1.o", [("a", "strong")]), ("a2.o", [("a", "strong")])], False),
        ])
        # Index order: first member providing a is pulled; second never is.
        self.assertEqual(
            [e["member"] for e in r["extraction_order"]], ["a1.o"]
        )

    def test_archive_member_with_duplicate_strong_rejected_at_member(self) -> None:
        # a.o pulled for a; it also strong-defines b, while earlier object
        # already strongly defined b => reject at the extraction site.
        eng = build_engine([
            ("obj", "main.o",
             [("main", "strong"), ("a", "undef"), ("b", "strong")], False),
            ("arc", "lib.a",
             [("a.o", [("a", "strong"), ("b", "strong")])], False),
        ])
        with self.assertRaises(LinkRejected) as cm:
            eng.run()
        p = cm.exception.payload
        self.assertEqual(p["detail"]["rule"], "duplicate_strong_definition")
        self.assertEqual(p["location"]["item_name"], "lib.a")
        self.assertEqual(p["location"]["member"], "a.o")
        self.assertEqual(
            [e["member"] for e in p["extraction_order"]], ["a.o"]
        )


class GroupSemantics(unittest.TestCase):
    def test_cross_archive_cycle_fails_without_group(self) -> None:
        # main needs x; liby (y -> x) is passed first and its member is not
        # indexed under x, so nothing is pulled there; libx then pulls x.o
        # which references y -- defined in an archive already passed, so the
        # link fails with y unresolved.
        eng = build_engine([
            ("obj", "main.o", [("main", "strong"), ("x", "undef")], False),
            ("arc", "liby.a", [("y.o", [("y", "strong"), ("x", "undef")])], False),
            ("arc", "libx.a", [("x.o", [("x", "strong"), ("y", "undef")])], False),
        ])
        with self.assertRaises(LinkRejected) as cm:
            eng.run()
        self.assertEqual(cm.exception.payload["detail"]["rule"], "undefined_at_close")
        self.assertEqual(
            cm.exception.payload["undefined_at_failure"], ["y"]
        )
        self.assertEqual(
            [e["member"] for e in cm.exception.payload["extraction_order"]],
            ["x.o"],
        )

    def test_cross_archive_cycle_closes_inside_group(self) -> None:
        r = run([
            ("obj", "main.o", [("main", "strong"), ("x", "undef")], False),
            ("arc", "liby.a", [("y.o", [("y", "strong"), ("x", "undef")])], True),
            ("arc", "libx.a", [("x.o", [("x", "strong"), ("y", "undef")])], True),
        ])
        self.assertEqual(r["status"], "accepted")
        pulled = {(e["item_name"], e["member"]) for e in r["extraction_order"]}
        self.assertEqual(
            pulled, {("libx.a", "x.o"), ("liby.a", "y.o")}
        )
        group_rounds = [x for x in r["rounds"] if x["scope"] == "group"]
        # Round 2 closes the cycle; round 3 extracts nothing and terminates.
        self.assertGreaterEqual(len(group_rounds), 2)
        # Undefined-set snapshots per round are recorded.
        self.assertIn("undefined_before", group_rounds[0])
        terminations = [x for x in group_rounds if not x["extracted"]]
        self.assertTrue(terminations)

    def test_group_fixpoint_terminates_after_extra_rounds(self) -> None:
        # Backward dependency: round 1 only pulls r (provides c, refs a);
        # a lives in l1 whose provider p was skipped on the first pass.
        # Round 2 pulls p (a, refs b) and, via the same-archive cascade, q.
        # Round 3 extracts nothing and the group reaches its fixpoint.
        r = run([
            ("obj", "main.o", [("main", "strong"), ("c", "undef")], False),
            ("arc", "l1.a",
             [("p.o", [("a", "strong"), ("b", "undef")]),
              ("q.o", [("b", "strong")])], True),
            ("arc", "l2.a",
             [("mid.o", [("m", "strong")])], True),
            ("arc", "l3.a",
             [("r.o", [("c", "strong"), ("a", "undef")])], True),
        ])
        self.assertEqual(r["status"], "accepted")
        self.assertEqual(
            [(e["item_name"], e["member"]) for e in r["extraction_order"]],
            [("l3.a", "r.o"), ("l1.a", "p.o"), ("l1.a", "q.o")],
        )
        group_rounds = [x for x in r["rounds"] if x["scope"] == "group"]
        self.assertGreaterEqual(len(group_rounds), 2)
        self.assertEqual(group_rounds[0]["undefined_before"], ["a"])
        self.assertTrue(any(not x["extracted"] for x in group_rounds))

    def test_duplicate_strong_inside_group_still_rejected(self) -> None:
        # Both members are needed (a and b), but a2.o carries a second
        # strong definition of a: the cycle-closing rescans cannot pardon it.
        eng = build_engine([
            ("obj", "main.o",
             [("main", "strong"), ("a", "undef"), ("b", "undef")], False),
            ("arc", "l1.a", [("a.o", [("a", "strong")])], True),
            ("arc", "l2.a", [("a2.o", [("b", "strong"), ("a", "strong")])], True),
        ])
        with self.assertRaises(LinkRejected) as cm:
            eng.run()
        self.assertEqual(cm.exception.payload["detail"]["rule"],
                         "duplicate_strong_definition")
        self.assertEqual(cm.exception.payload["location"]["member"], "a2.o")


if __name__ == "__main__":
    unittest.main(verbosity=2)
