"""High level audit entry point: decode inputs, classify, run arbitration."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from .ar import ArError, parse_ar
from .elf import ELFError, parse_elf
from .linker import Engine, InputItem, LinkRejected, Location

MAX_ITEMS = 12
AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_BYTES = 64 * 1024 * 1024  # reject absurd payloads early


class InvalidRequest(ValueError):
    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class RawItem:
    name: str
    grouped: bool
    data: bytes
    sha256: str
    size: int
    encoding: str


def _decode_item(payload: dict, position: int) -> RawItem:
    if not isinstance(payload, dict):
        raise InvalidRequest(f"item {position} must be an object", "items")
    name = payload.get("name") or f"input{position}"
    if not isinstance(name, str) or not name.strip() or len(name) > 255:
        raise InvalidRequest(f"item {position} has an invalid name", f"items[{position}].name")
    grouped = bool(payload.get("grouped", False))
    content = payload.get("content_base64")
    if not isinstance(content, str):
        raise InvalidRequest(
            f"item {position}: content_base64 is required and must be a string",
            f"items[{position}].content_base64",
        )
    # Strict canonical Base64 (standard alphabet, correct padding only).
    try:
        data = base64.b64decode(content.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidRequest(
            f"item {position} ({name}): content is not valid canonical Base64: {exc}",
            f"items[{position}].content_base64",
        ) from exc
    if not data:
        raise InvalidRequest(
            f"item {position} ({name}): decoded payload is empty",
            f"items[{position}].content_base64",
        )
    if len(data) > MAX_BYTES:
        raise InvalidRequest(
            f"item {position} ({name}): decoded payload exceeds {MAX_BYTES} bytes",
            f"items[{position}].content_base64",
        )
    return RawItem(
        name=name.strip(),
        grouped=grouped,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        encoding="base64",
    )


def validate_request(body: dict) -> tuple[str, list[RawItem]]:
    if not isinstance(body, dict):
        raise InvalidRequest("request body must be a JSON object")
    audit_id = body.get("audit_id")
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.match(audit_id):
        raise InvalidRequest(
            "audit_id is required: 1-64 chars, letters/digits/._-, start alphanumeric",
            "audit_id",
        )
    items = body.get("items")
    if not isinstance(items, list) or not items:
        raise InvalidRequest("items must be a non-empty array", "items")
    if len(items) > MAX_ITEMS:
        raise InvalidRequest(f"at most {MAX_ITEMS} link inputs are allowed", "items")
    decoded = [_decode_item(it, pos + 1) for pos, it in enumerate(items)]
    return audit_id, decoded


def _fingerprint(items: list[RawItem]) -> str:
    h = hashlib.sha256()
    for it in items:
        h.update(len(it.name).to_bytes(2, "little"))
        h.update(it.name.encode("utf-8"))
        h.update(b"\x01" if it.grouped else b"\x00")
        h.update(it.sha256.encode("ascii"))
    return h.hexdigest()


def perform_audit(audit_id: str, items: list[RawItem]) -> dict:
    """Parse every input in command-line order and run the link engine.

    Parsing failures are reported at their first trigger position; parsing is
    performed eagerly (left to right) so a corrupt later input cannot be
    hidden by an earlier arbitration failure.
    """
    parsed: list[InputItem] = []
    input_meta = []
    for pos, raw in enumerate(items, start=1):
        loc = Location(pos, raw.name)
        head = raw.data[:8]
        kind = "unknown"
        try:
            if head[:4] == b"\x7fELF":
                kind = "object"
                obj = parse_elf(raw.data)
                parsed.append(
                    InputItem(index=pos, name=raw.name, grouped=raw.grouped,
                              kind="object", obj=obj)
                )
            elif head == b"!<arch>\n" or raw.data.startswith(b"!<thin>"):
                kind = "archive"
                archive = parse_ar(raw.data)
                parsed.append(
                    InputItem(index=pos, name=raw.name, grouped=raw.grouped,
                              kind="archive", archive=archive)
                )
            else:
                raise ELFError(
                    "input is neither an ELF64 object nor a GNU ar archive "
                    f"(first bytes: {head[:4].hex()})"
                )
        except (ELFError, ArError) as exc:
            return {
                "status": "rejected",
                "audit_id": audit_id,
                "message": f"illegal member at command-line position {pos}: {exc}",
                "rejection": {
                    "rule": "illegal_member",
                    "location": loc.as_dict(),
                    "symbol": None,
                    "detail": {"parser": kind, "reason": str(exc)},
                },
                "extraction_order": [],
                "rounds": [],
                "decisions": [],
                "events": [],
                "undefined_at_failure": [],
                "input_fingerprint": _fingerprint(items),
                "inputs": _input_meta(items, input_meta),
            }
        n_defs = (
            len([s for s in parsed[-1].obj.symbols if s.defined])
            if kind == "object"
            else sum(len(m.elf.symbols) for m in parsed[-1].archive.members)
        )
        meta = {
            "position": pos,
            "name": raw.name,
            "kind": kind,
            "grouped": raw.grouped,
            "size": raw.size,
            "sha256": raw.sha256,
        }
        if kind == "archive":
            arc = parsed[-1].archive
            meta["members"] = [
                {
                    "name": m.name,
                    "header_offset": m.header_offset,
                    "size": m.size,
                    "indexed_symbols": list(m.indexed_symbols),
                }
                for m in arc.member_order
            ]
            meta["index_entries"] = len(arc.index)
        else:
            syms = parsed[-1].obj.symbols
            meta["symbols"] = [
                {"name": s.name, "kind": s.label} for s in syms
            ]
            meta["defined_symbol_count"] = n_defs
        input_meta.append(meta)

    engine = Engine(items=parsed)
    try:
        result = engine.run()
    except LinkRejected as fail:
        rej = fail.payload
        return {
            "status": "rejected",
            "audit_id": audit_id,
            "message": rej["message"],
            "rejection": {
                "rule": rej["detail"].get("rule", "link_error"),
                "location": rej["location"],
                "symbol": rej["symbol"],
                "detail": rej["detail"],
            },
            "extraction_order": rej["extraction_order"],
            "rounds": rej["rounds"],
            "decisions": rej["decisions"],
            "events": engine.events,
            "undefined_at_failure": rej["undefined_at_failure"],
            "input_fingerprint": _fingerprint(items),
            "inputs": _input_meta(items, input_meta),
        }

    result["audit_id"] = audit_id
    result["input_fingerprint"] = _fingerprint(items)
    result["inputs"] = _input_meta(items, input_meta)
    return result


def _input_meta(items: list[RawItem], parsed_meta: list[dict]) -> list[dict]:
    by_pos = {m["position"]: m for m in parsed_meta}
    out = []
    for pos, raw in enumerate(items, start=1):
        if pos in by_pos:
            out.append(by_pos[pos])
        else:
            out.append(
                {
                    "position": pos,
                    "name": raw.name,
                    "kind": "unparseable",
                    "grouped": raw.grouped,
                    "size": raw.size,
                    "sha256": raw.sha256,
                }
            )
    return out
