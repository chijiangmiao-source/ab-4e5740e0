"""Left-to-right static link arbitration for the offline load audit.

The engine models the observable semantics of ``ld`` command-line order for
relocatable objects and GNU symbol-index archives:

* objects are included in full at the position they appear;
* a normal archive is visited once at its position; the archive is then
  internally rescanned over its symbol index because members pulled in may
  themselves reference later members of the *same* archive;
* a maximal run of consecutive ``grouped`` entries (``--start-group`` /
  ``--end-group``) is rescanned as a whole, round after round, until a full
  round extracts no new members -- this is what closes cross-archive
  reference cycles;
* each external symbol may satisfy at most one strong definition: a second
  strong definition is a fatal error, never a silent choice;
* weak definitions and tentative COMMON definitions yield to strong ones;
  GNU ld precedence (verified against binutils) is
  strong > COMMON > weak, first wins at equal precedence; a later COMMON
  therefore supersedes an earlier weak definition in both command orders;
* weak undefined references neither pull archive members nor fail the link;
  strong undefined references remaining at the end are fatal.

Every decision is recorded as structured evidence: first-trigger location,
extracted members and the undefined set observed at each round.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ar import Archive, ArMember
from .elf import ELFObject, STB_GLOBAL, STB_WEAK, SHN_COMMON

STRONG = "strong"
WEAK = "weak"
COMMON = "common"

_STRENGTH_RANK = {STRONG: 3, COMMON: 2, WEAK: 1}


class LinkRejected(Exception):
    """Fatal arbitration failure carrying the first-trigger evidence."""

    def __init__(self, payload: dict):
        super().__init__(payload["message"])
        self.payload = payload


@dataclass(frozen=True)
class Location:
    item_index: int  # 1-based command-line position
    item_name: str
    member: str | None = None  # archive member name when applicable

    def as_dict(self) -> dict:
        d = {"item_index": self.item_index, "item_name": self.item_name}
        if self.member is not None:
            d["member"] = self.member
        return d


@dataclass(frozen=True)
class InputItem:
    index: int  # 1-based command-line position
    name: str
    grouped: bool
    kind: str  # "object" | "archive"
    obj: ELFObject | None = None
    archive: Archive | None = None


@dataclass
class RefSite:
    location: Location
    weak: bool


@dataclass
class Provider:
    location: Location
    strength: str


@dataclass
class Engine:
    items: list[InputItem]
    events: list[dict] = field(default_factory=list)
    extraction_order: list[dict] = field(default_factory=list)
    rounds: list[dict] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)
    defined: dict[str, Provider] = field(default_factory=dict)
    # Strong undefined references drive extraction and final failure.
    undef: dict[str, list[RefSite]] = field(default_factory=dict)
    # Weak undefined references never pull; reported only if still open.
    weak_undef: dict[str, list[RefSite]] = field(default_factory=dict)
    _seq: int = 0

    # -- evidence helpers ---------------------------------------------------

    def _tick(self) -> int:
        self._seq += 1
        return self._seq

    def _undefined_snapshot(self) -> list[str]:
        return sorted(self.undef)

    def _record_round(self, scope: str, item_index: int, round_no: int) -> None:
        self.rounds.append(
            {
                "scope": scope,  # "archive" or "group"
                "item_index": item_index,
                "round": round_no,
                "undefined_before": self._undefined_snapshot(),
                "extracted": [],
            }
        )

    def _reject(self, message: str, location: Location, symbol: str | None,
                detail: dict | None = None) -> None:
        payload = {
            "message": message,
            "location": location.as_dict(),
            "symbol": symbol,
            "detail": detail or {},
            "extraction_order": list(self.extraction_order),
            "rounds": list(self.rounds),
            "decisions": list(self.decisions),
            "undefined_at_failure": self._undefined_snapshot(),
        }
        raise LinkRejected(payload)

    # -- symbol bookkeeping -------------------------------------------------

    def _reference(self, name: str, site: RefSite) -> None:
        if not name:
            return
        if name in self.defined:
            return
        if site.weak:
            self.weak_undef.setdefault(name, []).append(site)
            return
        # A strong reference supersedes a previously weak-only reference:
        # the symbol now must be resolved and may pull archive members.
        weak_sites = self.weak_undef.pop(name, [])
        bucket = self.undef.setdefault(name, [])
        if weak_sites:
            bucket.extend(weak_sites)
        bucket.append(site)

    def _define(self, name: str, strength: str, location: Location) -> None:
        existing = self.defined.get(name)
        if existing is None:
            self.defined[name] = Provider(location, strength)
            # Any pending reference (weak or strong) is now satisfied.
            self.undef.pop(name, None)
            self.weak_undef.pop(name, None)
            return

        if strength == STRONG and existing.strength == STRONG:
            self._reject(
                f"multiple strong definitions of {name!r}: new strong definition "
                "conflicts with an earlier strong definition",
                location,
                name,
                detail={
                    "rule": "duplicate_strong_definition",
                    "existing_provider": {
                        "location": existing.location.as_dict(),
                        "strength": existing.strength,
                    },
                    "rejected_provider": {
                        "location": location.as_dict(),
                        "strength": strength,
                    },
                },
            )

        new_rank = _STRENGTH_RANK[strength]
        old_rank = _STRENGTH_RANK[existing.strength]
        if new_rank > old_rank:
            self.decisions.append(
                {
                    "type": "supersede",
                    "symbol": name,
                    "chosen": {"location": location.as_dict(), "strength": strength},
                    "superseded": {
                        "location": existing.location.as_dict(),
                        "strength": existing.strength,
                    },
                    "rule": f"{strength}_over_{existing.strength}",
                    "seq": self._tick(),
                }
            )
            self.defined[name] = Provider(location, strength)
            self.undef.pop(name, None)
            self.weak_undef.pop(name, None)
        else:
            self.decisions.append(
                {
                    "type": "ignore_later_definition",
                    "symbol": name,
                    "chosen": {
                        "location": existing.location.as_dict(),
                        "strength": existing.strength,
                    },
                    "ignored": {"location": location.as_dict(), "strength": strength},
                    "rule": (
                        "equal_strength_first_wins"
                        if new_rank == old_rank
                        else f"keep_{existing.strength}_over_{strength}"
                    ),
                    "seq": self._tick(),
                }
            )

    def _object_definition_map(self, obj: ELFObject, location: Location) -> dict[str, str]:
        """Collapse an object's definitions, rejecting in-object strong clashes."""
        strongest: dict[str, str] = {}
        for sym in obj.symbols:
            if not sym.defined:
                continue
            if sym.shndx == SHN_COMMON:
                strength = COMMON if sym.binding == STB_GLOBAL else WEAK
            elif sym.binding == STB_GLOBAL:
                strength = STRONG
            else:
                strength = WEAK
            if strength == STRONG and strongest.get(sym.name) == STRONG:
                self._reject(
                    f"invalid member: {sym.name!r} has more than one strong "
                    "definition inside the same object",
                    location,
                    sym.name,
                    detail={"rule": "duplicate_strong_within_object"},
                )
            prev = strongest.get(sym.name)
            if prev is None or _STRENGTH_RANK[strength] > _STRENGTH_RANK[prev]:
                strongest[sym.name] = strength
        return strongest

    def _apply_object(self, obj: ELFObject, location: Location, included_as: str) -> None:
        """Apply one relocatable object: definitions first, then references."""
        self.events.append(
            {
                "type": "object_included",
                "seq": self._tick(),
                "as": included_as,
                "location": location.as_dict(),
            }
        )
        defs = self._object_definition_map(obj, location)
        for name, strength in defs.items():
            self._define(name, strength, location)
        for sym in obj.symbols:
            if sym.defined:
                continue
            self._reference(
                sym.name,
                RefSite(location=location, weak=sym.binding == STB_WEAK),
            )

    # -- archives -----------------------------------------------------------

    def _scan_archive_once(self, item: InputItem, round_no: int,
                           scope: str) -> list[ArMember]:
        """One index-ordered pass; returns newly extracted members."""
        archive = item.archive
        assert archive is not None
        before = set(self.undef)
        newly: list[ArMember] = []
        already = {m["member"] for m in self.extraction_order if m["item_index"] == item.index}
        for member, indexed in archive.indexed_members_in_order():
            if member.name in already:
                continue
            triggers = sorted(set(indexed) & before)
            if not triggers:
                continue
            loc = Location(item.index, item.name, member.name)
            newly.append(member)
            self.extraction_order.append(
                {
                    "seq": self._tick(),
                    "item_index": item.index,
                    "item_name": item.name,
                    "member": member.name,
                    "member_header_offset": member.header_offset,
                    "triggered_by": triggers,
                    "scope": scope,
                    "round": round_no,
                    "location": loc.as_dict(),
                }
            )
            self.rounds[-1]["extracted"].append(
                {"member": member.name, "triggered_by": triggers}
            )
            self._apply_object(member.elf, loc, included_as="archive-member")
            already.add(member.name)
            # Internal cascade: newly created undefined symbols may match
            # later members during this same pass; subsequent passes handle
            # members that appeared earlier in the index.
            before = set(self.undef)
        return newly

    def _process_archive(self, item: InputItem, first_round: int = 1,
                         scope: str = "archive") -> int:
        """Process a normal archive to its internal fixpoint.

        Returns the number of the last round performed.
        """
        archive = item.archive
        assert archive is not None
        round_no = first_round
        self.events.append(
            {
                "type": "archive_visited",
                "seq": self._tick(),
                "item_index": item.index,
                "item_name": item.name,
                "indexed_members": len(
                    {m.header_offset for _, m in archive.index}
                ),
                "index_entries": len(archive.index),
                "scope": scope,
            }
        )
        while True:
            self._record_round("archive", item.index, round_no)
            newly = self._scan_archive_once(item, round_no, scope)
            if not newly:
                break
            round_no += 1
        return round_no

    def _process_group(self, run: list[InputItem]) -> None:
        start = run[0].index
        end = run[-1].index
        self.events.append(
            {
                "type": "group_start",
                "seq": self._tick(),
                "item_index_start": start,
                "item_index_end": end,
            }
        )
        # Round 1: ordinary left-to-right handling of every entry in the run.
        group_round = 1
        for item in run:
            loc = Location(item.index, item.name)
            if item.kind == "object":
                self._apply_object(item.obj, loc, included_as="object")
            else:
                self._process_archive(item, first_round=1, scope="group-round-1")
        # Further rounds: rescan every archive in the run, in order, until a
        # whole group round extracts nothing.  Objects were fully included.
        archives = [it for it in run if it.kind == "archive"]
        while True:
            group_round += 1
            self._record_round("group", start, group_round)
            group_record = self.rounds[-1]
            extracted_any = False
            for item in archives:
                before_pass = len(self.extraction_order)
                self._process_archive(
                    item, first_round=1, scope=f"group-round-{group_round}"
                )
                # _process_archive appends its own archive rounds; attribute
                # any extractions to the enclosing group round record too.
                for ev in self.extraction_order[before_pass:]:
                    group_record["extracted"].append(
                        {
                            "item_index": item.index,
                            "member": ev["member"],
                            "triggered_by": ev["triggered_by"],
                        }
                    )
                    extracted_any = True
            if not extracted_any:
                break
        self.events.append(
            {
                "type": "group_end",
                "seq": self._tick(),
                "item_index_start": start,
                "item_index_end": end,
                "rounds": group_round,
            }
        )

    # -- entry point --------------------------------------------------------

    def run(self) -> dict:
        i = 0
        while i < len(self.items):
            if self.items[i].grouped:
                j = i
                while j + 1 < len(self.items) and self.items[j + 1].grouped:
                    j += 1
                self._process_group(self.items[i : j + 1])
                i = j + 1
                continue

            item = self.items[i]
            loc = Location(item.index, item.name)
            if item.kind == "object":
                self._apply_object(item.obj, loc, included_as="object")
            else:
                self._process_archive(item)
            i += 1

        # Final closure check.
        unresolved = sorted(self.undef)
        if unresolved:
            first = unresolved[0]
            site = self.undef[first][0].location
            refs = {
                sym: [s.location.as_dict() for s in sites]
                for sym, sites in self.undef.items()
            }
            self._reject(
                f"undefined reference at end of link: {first!r} and "
                f"{len(unresolved) - 1} more symbol(s) remain unresolved",
                site,
                first,
                detail={"rule": "undefined_at_close", "all_undefined": unresolved,
                        "reference_sites": refs},
            )

        weak_open = sorted(self.weak_undef)
        return {
            "status": "accepted",
            "extraction_order": self.extraction_order,
            "rounds": self.rounds,
            "decisions": self.decisions,
            "events": self.events,
            "weak_unresolved": [
                {"symbol": s, "reference_sites": [x.location.as_dict() for x in sites]}
                for s, sites in sorted(self.weak_undef.items())
            ],
            "defined_symbols": sorted(self.defined),
        }
