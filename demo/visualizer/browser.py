"""Playwright wrapper that drives the portal UI in a VISIBLE browser.

The demo video records this window. The payloads typed here are the agent's
REAL chosen payloads (passed in by the orchestrator), so what's on screen is a
faithful re-enactment of the agent's real attack through the actual UI — the
page changes because the real request really worked.

Headed + slow_mo so typing and page changes are visible on camera.
"""

from __future__ import annotations

import time

from playwright.sync_api import sync_playwright


class PortalBrowser:
    def __init__(self, base_url: str, slow_mo_ms: int = 70, type_delay_ms: int = 75):
        self.base_url = base_url.rstrip("/")
        self.slow_mo_ms = slow_mo_ms
        self.type_delay_ms = type_delay_ms
        self._pw = None
        self._browser = None
        self.page = None

    def __enter__(self):
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=False, slow_mo=self.slow_mo_ms,
                                                  args=["--window-size=1100,860"])
        ctx = self._browser.new_context(viewport={"width": 1100, "height": 860})
        self.page = ctx.new_page()
        return self

    def __exit__(self, *exc):
        try:
            if self._browser:
                self._browser.close()
        finally:
            if self._pw:
                self._pw.stop()

    # --- primitives --------------------------------------------------------
    def goto(self, path: str = "/"):
        self.page.goto(f"{self.base_url}{path}")
        self.page.wait_for_load_state("domcontentloaded")

    def type_into(self, selector: str, text: str):
        el = self.page.wait_for_selector(selector, timeout=10000)
        el.click()
        el.fill("")
        el.type(text, delay=self.type_delay_ms)

    def click(self, selector: str):
        self.page.click(selector)

    def nav_click(self, selector: str, settle: float = 1.5):
        """Click a visible on-page link and wait for the new page to load, so
        the navigation to another section is obvious on camera."""
        self.page.click(selector)
        self.page.wait_for_load_state("domcontentloaded")
        self.pause(settle)

    def pause(self, seconds: float):
        time.sleep(seconds)

    def set_session_token(self, token: str):
        """Seed the applicant session token the UI pages read from
        sessionStorage, so viewer pages can call the authed APIs."""
        self.page.evaluate(
            "(t) => { sessionStorage.setItem('session_token', t);"
            " sessionStorage.setItem('matched_user','applicant'); }", token,
        )

    def login_ui(self, username: str, password: str, expect_success: bool = True, settle: float = 1.2):
        """Drive the real login form (used both for the SQLi beat and to
        establish a benign applicant session for other beats)."""
        self.goto("/")
        self.type_into("#username", username)
        self.type_into("#password", password)
        self.pause(0.4)
        self.click("#loginForm button[type=submit]")
        self.pause(settle)
