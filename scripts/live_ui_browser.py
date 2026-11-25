#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The browser half of `scripts/live_iya_sts.py --ui` (#41).

Runs INSIDE Playwright's official Python image (never on the host), started by
the live script with --network host. It drives a real headless Chromium
through the demo's own UI: the home page's Sign in, the GNAP interaction
redirect to iya-sts's sign-in and approval pages, back to the demo's
/callback, then the two PEP-protected pages, opened from the top bar's links
and by address. For each it asserts the HTTP status of the page's response
and the text the page shows.

1. The allowed user (attr1=abc123): GET /attribute-protected 200, GET
   /orders/42 200, POST /orders/42 403 (page.request, with the browser's
   cookies). Then Sign out from the user menu; both pages are 401.
2. The denied user (attr1=not-abc123), in a FRESH browser context (new
   cookies), because GNAP has no prompt to make iya-sts ask again and its
   sign-on session would otherwise sign the allowed user straight back in:
   GET /attribute-protected 403, GET /orders/42 200, POST /orders/42 403.

Environment: DEMO_URL, UI_OUT (the screenshots and summary.json), and per
user UI_ALLOWED_USER / UI_ALLOWED_SECRET, UI_DENIED_USER / UI_DENIED_SECRET.
A password is typed into the page and never printed. iya-sts's listener is
the fresh development container's own self-signed chain, so the browser
context ignores HTTPS errors on it; the demo is plain HTTP on loopback.

Prints the JSON summary last, and exits 1 on any mismatch.
"""

import json
import os
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

DEMO = os.environ["DEMO_URL"].rstrip("/")
OUT = Path(os.environ.get("UI_OUT") or "/out")
STEP_TIMEOUT = 30


class Run:
    def __init__(self):
        self.checks = []
        self.shots = []

    def check(self, who, what, got, want):
        ok = got == want
        self.checks.append({"user": who, "check": what, "got": got, "want": want, "ok": ok})
        print(f"{'ok  ' if ok else 'FAIL'} {who}: {what}: {got!r} (want {want!r})", flush=True)
        return ok

    def shot(self, page, who, name):
        path = OUT / f"{who}-{name}.png"
        page.screenshot(path=str(path), full_page=True)
        self.shots.append(path.name)


def at_demo(url):
    return url.startswith(DEMO + "/") or url == DEMO


def visible(page, selector):
    try:
        return page.locator(selector).first.is_visible()
    except Exception:
        return False


def click_and_wait(page, selector):
    """Clicks, then waits until the page has moved on (a new URL or the
    control gone). iya-sts's pages post from script and then set location."""
    before = page.url
    page.locator(selector).first.click()
    deadline = time.time() + STEP_TIMEOUT
    while time.time() < deadline:
        if page.url != before or not visible(page, selector):
            return
        page.wait_for_timeout(200)
    raise RuntimeError(f"{selector} did not move the page on from {before}")


def sign_in(run, page, who, username, password):
    """The demo's Sign in, through iya-sts, back to the demo signed in."""
    callbacks = []
    page.on("response", lambda r: callbacks.append(r.status) if r.url.split("?")[0] == DEMO + "/callback" else None)
    home = page.goto(DEMO + "/")
    run.check(who, "GET / (signed out) status", home.status, 200)
    run.shot(page, who, "01-home")
    click_and_wait(page, "a.button.primary[href='/login']")
    seen = []
    deadline = time.time() + 120
    while time.time() < deadline:
        page.wait_for_load_state("load")
        if at_demo(page.url) and "/login" not in page.url:
            break
        if visible(page, "#password"):
            if visible(page, "#username") and page.locator("#username").first.is_editable():
                page.locator("#username").first.fill(username)
            page.locator("#password").first.fill(password)
            seen.append("sign-in")
            run.shot(page, who, "02-iya-sts-sign-in")
            click_and_wait(page, "#kc-login")
        elif visible(page, "#username"):
            page.locator("#username").first.fill(username)
            seen.append("username")
            click_and_wait(page, "#kc-login")
        elif visible(page, "#gnap-allow"):
            seen.append("gnap-approval")
            run.shot(page, who, "03-iya-sts-gnap-approval")
            click_and_wait(page, "#gnap-allow")
        elif visible(page, "#post-login-skip"):
            seen.append("post-login-skip")
            click_and_wait(page, "#post-login-skip")
        elif visible(page, "#mfa-setup-skip"):
            seen.append("mfa-setup-skip")
            click_and_wait(page, "#mfa-setup-skip")
        elif visible(page, "button[value=allow]"):
            seen.append("consent")
            click_and_wait(page, "button[value=allow]")
        else:
            page.wait_for_timeout(300)
    else:
        run.shot(page, who, "XX-stuck")
        raise RuntimeError(f"{who}: the sign-in did not come back to the demo (last at {page.url.split('?')[0]}, steps {seen})")
    page.wait_for_load_state("load")
    run.check(who, "iya-sts asked for a password", "sign-in" in seen, True)
    run.check(who, "the browser came back through /callback (303)", callbacks[:1], [303])
    run.check(who, "the demo says who signed in", page.locator("h1").first.inner_text().startswith("Signed in as"), True)
    run.shot(page, who, "04-signed-in")
    return seen


def wait_for_pep(page):
    """The local PEP registered and holding its policy (it starts with the
    demo's GNAP client, at the first sign-in)."""
    deadline = time.time() + 60
    last = {}
    while time.time() < deadline:
        answer = page.request.get(DEMO + "/pep-status")
        if answer.status == 200:
            last = answer.json()
            if last.get("registered") and (last.get("policy") or {}).get("held"):
                return last
        page.wait_for_timeout(500)
    raise RuntimeError(f"the demo's PEP did not get ready: {json.dumps(last)[:400]}")


def protected(run, page, who, path, link, want, text):
    """Opens `path` by its top-bar link, then by address; both responses
    must be `want`, and the page must show `text`."""
    with page.expect_response(lambda r: r.url == DEMO + path) as clicked:
        page.locator("nav.site-nav a", has_text=link).click()
    page.wait_for_load_state("load")
    run.check(who, f"GET {path} from the top bar's '{link}' link: status", clicked.value.status, want)
    run.check(who, f"GET {path} from the link: page shows {text!r}", text in page.locator("main").inner_text(), True)
    run.shot(page, who, f"05-{path.strip('/').replace('/', '-')}-link")
    answer = page.goto(DEMO + path)
    run.check(who, f"GET {path} by address: status", answer.status, want)
    run.check(who, f"GET {path} by address: page shows {text!r}", text in page.locator("main").inner_text(), True)
    run.shot(page, who, f"06-{path.strip('/').replace('/', '-')}")


def write_order(run, page, who):
    """POST /orders/42 (a write) with the browser context's cookies."""
    answer = page.request.post(DEMO + "/orders/42")
    body = answer.text()
    run.check(who, "POST /orders/42 (page.request, the browser's cookies): status", answer.status, 403)
    run.check(who, "POST /orders/42: the PEP denied write", "The PEP denied <code>write</code> on order 42" in body, True)


def sign_out(run, page, who):
    page.goto(DEMO + "/")
    page.locator("details.acct-menu > summary").click()
    run.shot(page, who, "07-user-menu")
    page.locator("details.acct-menu form[action='/logout'] button").click()
    page.wait_for_load_state("load")
    run.check(who, "after Sign out the home page offers Sign in", visible(page, "a.button.primary[href='/login']"), True)
    for path in ("/attribute-protected", "/orders/42"):
        answer = page.goto(DEMO + path)
        run.check(who, f"GET {path} signed out: status", answer.status, 401)
    run.shot(page, who, "08-signed-out")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    run = Run()
    users = {
        "allowed": (os.environ["UI_ALLOWED_USER"], os.environ["UI_ALLOWED_SECRET"]),
        "denied": (os.environ["UI_DENIED_USER"], os.environ["UI_DENIED_SECRET"]),
    }
    error = None
    pep = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            # The allowed user.
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            username, password = users["allowed"]
            sign_in(run, page, "allowed", username, password)
            pep = wait_for_pep(page)
            protected(run, page, "allowed", "/attribute-protected", "Attribute-protected", 200,
                      "The PEP permitted it: your attr1 is abc123.")
            protected(run, page, "allowed", "/orders/42", "Order 42", 200, "The PEP permitted read.")
            write_order(run, page, "allowed")
            sign_out(run, page, "allowed")
            context.close()
            # The denied user: a fresh context, so iya-sts asks again.
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            username, password = users["denied"]
            sign_in(run, page, "denied", username, password)
            protected(run, page, "denied", "/attribute-protected", "Attribute-protected", 403, "The PEP denied it")
            protected(run, page, "denied", "/orders/42", "Order 42", 200, "The PEP permitted read.")
            write_order(run, page, "denied")
            context.close()
        except Exception as err:  # reported in the summary; the run fails
            error = str(err)
            print(f"FAIL {error}", flush=True)
        finally:
            browser.close()
    failed = [c for c in run.checks if not c["ok"]]
    summary = {
        "ok": error is None and not failed and bool(run.checks),
        "checks": len(run.checks),
        "failed": failed,
        "error": error,
        "results": {f"{c['user']}: {c['check']}": c["got"] for c in run.checks},
        "pepMode": pep.get("mode"),
        "screenshots": run.shots,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
