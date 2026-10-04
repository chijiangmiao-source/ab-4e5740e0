#!/usr/bin/env python3
"""One-shot verification run.

Executes, in order, and reports a single process exit code:

  1. parser/linker rule tests (raw-byte ELF/ar validation + link semantics);
  2. frontend build check (tsc --noEmit + vite production build);
  3. API/HTTP smoke against the live compose services, including the archive
     closure scenario (cross-archive cycle rejected without a group, closed
     inside one), frozen-conclusion reopen, fingerprint conflicts and all
     rejection paths.

Environment:
  API_BASE  default http://api:8080
  WEB_BASE  default http://web:80
  SKIP_NPM=1 skips step 2 (used when node_modules/dist are pre-provisioned)
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"

API_BASE = os.environ.get("API_BASE", "http://api:8080").rstrip("/")
WEB_BASE = os.environ.get("WEB_BASE", "http://web:80").rstrip("/")

GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

failures: list[str] = []
checks = 0


def step(title: str) -> None:
    print(f"\n{BOLD}{CYAN}=== {title} ==={RESET}", flush=True)


def ok(msg: str) -> None:
    global checks
    checks += 1
    print(f"  {GREEN}PASS{RESET} {msg}", flush=True)


def bad(msg: str) -> None:
    global checks
    checks += 1
    failures.append(msg)
    print(f"  {RED}FAIL{RESET} {msg}", flush=True)


def check(cond: bool, msg: str) -> bool:
    if cond:
        ok(msg)
    else:
        bad(msg)
    return cond


# -- step 1 -------------------------------------------------------------------

def run_rule_tests() -> None:
    step("1/3 解析规则与链接语义测试 (unittest)")
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_parsers",
         "tests.test_linker", "-v"],
        cwd=BACKEND,
    )
    if proc.returncode == 0:
        ok("parser + linker rule tests exit 0")
    else:
        bad(f"rule tests exited {proc.returncode}")


# -- step 2 -------------------------------------------------------------------

def run_frontend_build() -> None:
    step("2/3 前端构建检查 (tsc --noEmit && vite build)")
    if os.environ.get("SKIP_NPM") == "1":
        ok("npm build skipped (SKIP_NPM=1)")
        return
    npm = "npm.cmd" if os.name == "nt" else "npm"
    cache = str(ROOT / ".npm-cache")
    install = subprocess.run(
        [npm, "ci", "--cache", cache, "--no-audit", "--no-fund"],
        cwd=FRONTEND,
    )
    if install.returncode != 0:
        bad("npm ci failed")
        return
    ok("npm ci")
    build = subprocess.run([npm, "run", "build"], cwd=FRONTEND)
    if build.returncode == 0 and (FRONTEND / "dist" / "index.html").is_file():
        ok("vite production build produced dist/index.html")
    else:
        bad("frontend build failed")


# -- step 3 -------------------------------------------------------------------

def http(method: str, url: str, payload: dict | None = None,
         timeout: int = 10) -> tuple[int, dict | str]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    try:
        return status, json.loads(raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, raw.decode(errors="replace")


def wait_for(url: str, what: str, attempts: int = 60) -> None:
    for i in range(attempts):
        try:
            status, body = http("GET", url)
            if status == 200:
                ok(f"{what} reachable: {url} -> {body if isinstance(body, str) else body.get('status')}")
                return
        except OSError:
            pass
        time.sleep(1)
    bad(f"{what} not reachable after {attempts}s: {url}")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# Unique per process so repeated verify runs always exercise create (201),
# reopen (200) and conflict (409) semantics against a durable database.
RUN_TOKEN = str(int(time.time() * 1000))[-10:]
ID_CYCLE_NO_GROUP = f"SMOKE-CYCLE-UNGROUPED-{RUN_TOKEN}"
ID_CYCLE_GROUP = f"SMOKE-CYCLE-GROUPED-{RUN_TOKEN}"
ID_DUP_STRONG = f"SMOKE-DUPSTRONG-{RUN_TOKEN}"
ID_CORRUPT = f"SMOKE-CORRUPT-INDEX-{RUN_TOKEN}"
ID_BAD_B64 = f"SMOKE-BADB64-{RUN_TOKEN}"
ID_TOO_MANY = f"SMOKE-TOOMANY-{RUN_TOKEN}"

# Fixtures are produced with the same raw-byte builder the rule tests use.
sys.path.insert(0, str(BACKEND))
from tests.fixtures import make_archive, make_elf_object  # noqa: E402


def cycle_payload(audit_id: str, grouped: bool) -> dict:
    main = make_elf_object([("main", "strong"), ("x", "undef")])
    liby = make_archive([("y.o", make_elf_object(
        [("y", "strong"), ("x", "undef")]))])
    libx = make_archive([("x.o", make_elf_object(
        [("x", "strong"), ("y", "undef")]))])
    return {
        "audit_id": audit_id,
        "items": [
            {"name": "main.o", "content_base64": b64(main)},
            {"name": "liby.a", "content_base64": b64(liby), "grouped": grouped},
            {"name": "libx.a", "content_base64": b64(libx), "grouped": grouped},
        ],
    }


def run_http_smoke() -> None:
    step("3/3 活服务 API/HTTP 冒烟（归档闭合场景）")
    wait_for(f"{API_BASE}/health", "api health endpoint")
    wait_for(f"{WEB_BASE}/health", "web health endpoint (proxied)")

    # 3.1 archive closure: the same cross-archive cycle must fail outside a
    # group and close (fixpoint extraction) inside one.
    status, rejected = http(
        "POST", f"{API_BASE}/api/audits",
        cycle_payload(ID_CYCLE_NO_GROUP, False))
    if check(status == 201 and isinstance(rejected, dict)
             and rejected.get("status") == "rejected",
             "cross-archive cycle WITHOUT group -> 201 rejected"):
        rej = rejected["rejection"]
        check(rej["rule"] == "undefined_at_close",
              "  rule=undefined_at_close")
        check(rejected["undefined_at_failure"] == ["y"],
              "  final undefined set evidence = [y]")
        check(rej["location"]["member"] == "x.o",
              "  first-trigger location pins member x.o in libx.a")
        check([e["member"] for e in rejected["extraction_order"]] == ["x.o"],
              "  extraction-order evidence present")

    status, accepted = http(
        "POST", f"{API_BASE}/api/audits",
        cycle_payload(ID_CYCLE_GROUP, True))
    if check(status == 201 and isinstance(accepted, dict)
             and accepted.get("status") == "accepted",
             "cross-archive cycle INSIDE group -> 201 accepted"):
        pulled = {(e["item_name"], e["member"]) for e in accepted["extraction_order"]}
        check(pulled == {("libx.a", "x.o"), ("liby.a", "y.o")},
              "  both cycle members extracted")
        group_rounds = [r for r in accepted["rounds"] if r["scope"] == "group"]
        check(any(not r["extracted"] for r in group_rounds),
              "  group rescanned to a no-extraction fixpoint round")
        check(any(r["undefined_before"] == ["y"] for r in group_rounds),
              "  per-round undefined-set evidence recorded ([y] before closure)")

    # 3.2 reopen the frozen accepted conclusion by its stable audit id.
    status, reopened = http("GET", f"{API_BASE}/api/audits/{ID_CYCLE_GROUP}")
    if check(status == 200 and isinstance(reopened, dict)
             and reopened.get("reopened") is True,
             "reopen frozen conclusion by audit_id -> 200 reopened=true"):
        check(reopened["input_fingerprint"] == accepted["input_fingerprint"],
              "  reopened conclusion is byte-identical (same fingerprint)")

    # 3.3 resubmit same id with different inputs -> 409, never overwritten.
    other = make_elf_object([("other", "strong")])
    status, conflict = http("POST", f"{API_BASE}/api/audits", {
        "audit_id": ID_CYCLE_GROUP,
        "items": [{"name": "other.o", "content_base64": b64(other)}],
    })
    check(status == 409 and isinstance(conflict, dict)
          and conflict.get("error") == "audit_id_conflict",
          "same audit_id with different inputs -> 409 audit_id_conflict")

    # 3.4 duplicate strong definitions are refused, never silently chosen.
    a1 = make_elf_object([("a", "strong")])
    a2 = make_elf_object([("a", "strong")])
    status, dup = http("POST", f"{API_BASE}/api/audits", {
        "audit_id": ID_DUP_STRONG,
        "items": [
            {"name": "a1.o", "content_base64": b64(a1)},
            {"name": "a2.o", "content_base64": b64(a2)},
        ],
    })
    if check(status == 201 and isinstance(dup, dict)
            and dup["status"] == "rejected"
            and dup["rejection"]["rule"] == "duplicate_strong_definition",
            "duplicate strong definitions -> rejected"):
        check(dup["rejection"]["location"]["item_index"] == 2,
              "  first trigger at command-line position 2")
        check(dup["rejection"]["detail"]["existing_provider"]["location"]
              ["item_name"] == "a1.o",
              "  earlier strong provider carried as evidence")

    # 3.5 corrupt archive index (claims a phantom definition).
    bad_arc = make_archive(
        [("x.o", make_elf_object([("x", "strong")]))],
        index=[("phantom", "x.o")])
    status, corrupt = http("POST", f"{API_BASE}/api/audits", {
        "audit_id": ID_CORRUPT,
        "items": [{"name": "libbad.a", "content_base64": b64(bad_arc)}],
    })
    if check(status == 201 and isinstance(corrupt, dict)
            and corrupt["status"] == "rejected"
            and corrupt["rejection"]["rule"] == "illegal_member",
            "corrupt archive index -> rejected illegal_member"):
        check(corrupt["rejection"]["location"]["item_index"] == 1,
              "  rejection pinned to first triggering input position")

    # 3.6 illegal Base64 -> 400 validation error.
    status, invalid = http("POST", f"{API_BASE}/api/audits", {
        "audit_id": ID_BAD_B64,
        "items": [{"name": "x.o", "content_base64": "@@@not-base64@@@"}],
    })
    check(status == 400 and isinstance(invalid, dict)
          and invalid.get("error") == "invalid_request",
          "non-canonical Base64 -> 400 invalid_request")

    # 3.7 more than twelve inputs -> 400.
    too_many = {
        "audit_id": ID_TOO_MANY,
        "items": [
            {"name": f"o{i}.o", "content_base64": b64(make_elf_object([]))}
            for i in range(13)
        ],
    }
    status, many = http("POST", f"{API_BASE}/api/audits", too_many)
    check(status == 400 and isinstance(many, dict),
          "thirteen inputs -> 400")

    # 3.8 unknown audit id reopen -> 404.
    status, missing = http("GET", f"{API_BASE}/api/audits/NO-SUCH-AUDIT-ID")
    check(status == 404 and isinstance(missing, dict)
          and missing.get("error") == "not_found",
          "reopen unknown audit_id -> 404")

    # 3.9 the real built page is served by the web tier: index HTML plus its
    # content-hashed JS asset, which carries the runtime-rendered audit UI.
    try:
        with urllib.request.urlopen(f"{WEB_BASE}/", timeout=10) as resp:
            page = resp.read().decode()
            web_status = resp.status
    except OSError:
        web_status, page = 0, ""
    js_ok = False
    if web_status == 200 and '<div id="app">' in page:
        import re

        m = re.search(r'src="(/assets/[^"]+\.js)"', page)
        if m:
            try:
                with urllib.request.urlopen(f"{WEB_BASE}{m.group(1)}", timeout=10) as r:
                    js = r.read().decode()
                js_ok = "离线装载链接审计" in js and "/api/audits" in js
            except OSError:
                js_ok = False
    check(web_status == 200 and js_ok,
          "web serves built audit page (index.html + hashed JS with real API calls)")
    status, asset = http("GET", f"{WEB_BASE}/health")
    check(status == 200 and isinstance(asset, dict) and asset.get("status") == "ok",
          "web /health proxies the API health endpoint")

    # 3.10 audits listing shows frozen conclusions.
    status, listing = http("GET", f"{API_BASE}/api/audits")
    ids = {a["audit_id"] for a in listing.get("audits", [])} if isinstance(listing, dict) else set()
    check(status == 200 and ID_CYCLE_GROUP in ids,
          "audits index lists frozen conclusions")


def main() -> int:
    print(f"{BOLD}link-audit verify — one-shot run{RESET}")
    print(f"API_BASE={API_BASE}  WEB_BASE={WEB_BASE}")
    run_rule_tests()
    run_frontend_build()
    run_http_smoke()

    print(f"\n{BOLD}=== summary ==={RESET}")
    print(f"checks: {checks}, failures: {len(failures)}")
    if failures:
        for f in failures:
            print(f"  {RED}- {f}{RESET}")
        print(f"{RED}VERIFY FAILED{RESET}")
        return 1
    print(f"{GREEN}VERIFY OK{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
