#!/usr/bin/env python3
"""
Phishing email triage (local, standard library only).

Reads .eml files (the format you get from "Download message" / "Save as") and
produces, for each email: authentication results (SPF / DKIM / DMARC), sender
analysis (display-name impersonation, Reply-To mismatch, lookalike domains,
spoofing of our own domain), links (visible text vs real destination),
attachments (type, SHA-256, HTML forms that collect passwords), social-engineering
language, a scored verdict, defanged IOCs and the recommended response.

Usage:
    python triage_email.py                         # all emails in data/emails
    python triage_email.py data/emails/E2-m365-password.eml
    python triage_email.py --json                  # machine-readable output
"""

from __future__ import annotations

import argparse
import csv
import email
import hashlib
import json
import os
import re
import sys
from email import policy
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

RISKY_EXTENSIONS = {".html", ".htm", ".shtml", ".svg", ".js", ".vbs", ".wsf", ".hta", ".exe", ".scr", ".msi",
                    ".iso", ".img", ".lnk", ".one", ".docm", ".xlsm", ".pptm", ".zip", ".7z", ".rar"}
FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com", "icloud.com",
            "mailbox.example"}
LANGUAGE = {
    "urgency": ["urgent", "immediately", "today", "within 24 hours", "right away", "asap", "before 5pm"],
    "credentials": ["password", "verify your account", "sign in", "login", "confirm your", "expires"],
    "payment": ["gift card", "wire transfer", "bank details", "invoice is overdue", "payment"],
    "secrecy": ["confidential", "don't tell", "keep this", "can't talk"],
    "threat": ["suspended", "will be deleted", "locked", "disabled"],
}
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a")]


# --------------------------------------------------------------------------- helpers

def load_trusted(path: str) -> Dict[str, str]:
    with open(path, encoding="utf-8", newline="") as fh:
        return {r["domain"].lower(): r["owner"] for r in csv.DictReader(fh)}


def load_directory(path: str) -> List[Dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip(" >").lower() if "@" in address else ""


def base_label(domain: str) -> str:
    """'login.micros0ft-account.example' -> 'micros0ft-account'  (label before the TLD)."""
    parts = [p for p in domain.lower().split(".") if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def normalize(label: str) -> str:
    out = label
    for a, b in HOMOGLYPHS:
        out = out.replace(a, b)
    return out


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str, trusted: Dict[str, str]) -> Optional[str]:
    """Return the trusted domain this one imitates, or None."""
    if not domain or domain in trusted or any(domain.endswith("." + t) for t in trusted):
        return None
    label = base_label(domain)
    norm = normalize(label)
    for t in trusted:
        tl = base_label(t)
        if len(tl) < 4:
            continue
        if norm == tl or (tl in norm and norm != label and tl in normalize(label)):
            return t
        if tl in label.split("-") or (tl in norm and label != tl):
            return t
        if 0 < levenshtein(norm, tl) <= 1 and len(tl) >= 6:
            return t
    return None


def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []
        self.forms: List[str] = []
        self.password_inputs = 0
        self._href: Optional[str] = None
        self._text: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            self._href, self._text = a.get("href", ""), []
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input" and (a.get("type") or "").lower() == "password":
            self.password_inputs += 1

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def parse_auth(value: str) -> Dict[str, str]:
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", value or "", re.IGNORECASE)
        out[mech] = m.group(1).lower() if m else "missing"
    return out


def origin_ip(msg) -> str:
    received = msg.get_all("Received") or []
    for hop in reversed(received):          # the bottom Received header is the first hop
        m = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", hop)
        if m:
            return m.group(1)
    return "-"


# --------------------------------------------------------------------------- analysis

def analyze(path: str, trusted: Dict[str, str], directory: List[Dict]) -> Dict:
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)
    our_domains = {d for d, owner in trusted.items() if owner == "CORP"}
    from_name, from_addr = email.utils.parseaddr(str(msg.get("From", "")))
    reply_name, reply_addr = email.utils.parseaddr(str(msg.get("Reply-To", "")))
    from_dom, reply_dom = domain_of(from_addr), domain_of(reply_addr)
    auth = parse_auth(str(msg.get("Authentication-Results", "")))

    text_parts, links, forms, pw_inputs, attachments = [], [], [], 0, []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        if filename:
            ext = os.path.splitext(filename.lower())[1]
            info = {"filename": filename, "type": ctype, "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(), "risky_extension": ext in RISKY_EXTENSIONS}
            if ext in (".html", ".htm", ".svg"):
                lp = LinkParser()
                lp.feed(payload.decode("utf-8", errors="ignore"))
                info["form_actions"] = lp.forms
                info["password_fields"] = lp.password_inputs
                forms += lp.forms
                pw_inputs += lp.password_inputs
            attachments.append(info)
            continue
        body = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
        if ctype == "text/html":
            lp = LinkParser()
            lp.feed(body)
            links += lp.links
            forms += lp.forms
            pw_inputs += lp.password_inputs
            text_parts.append(re.sub(r"<[^>]+>", " ", body))
        elif ctype == "text/plain":
            text_parts.append(body)
            links += [(u, u) for u in re.findall(r"https?://[^\s\"'<>]+", body)]
    text = " ".join(text_parts).lower()

    findings: List[Tuple[int, str]] = []

    def flag(points: int, why: str):
        findings.append((points, why))

    # authentication
    if auth["dmarc"] == "fail":
        flag(30, "DMARC fail: the From domain did not authorize this message")
    if auth["spf"] == "fail":
        flag(10, "SPF fail")
    if auth["dkim"] == "fail":
        flag(10, "DKIM fail")
    if from_dom in our_domains and auth["dmarc"] != "pass":
        flag(25, f"claims to come from OUR domain ({from_dom}) but is not authenticated: spoofing")
    if auth["dmarc"] in ("none", "missing") and from_dom not in trusted:
        flag(5, "sender domain has no DMARC policy")

    # sender
    look = lookalike_of(from_dom, trusted)
    if look:
        flag(30, f"lookalike domain: {from_dom} imitates {look}")
    if reply_dom and reply_dom != from_dom:
        flag(15, f"Reply-To ({reply_addr}) differs from From ({from_addr})")
    for person in directory:
        if person["name"].lower() in (from_name or "").lower() and from_addr.lower() != person["email"].lower():
            flag(30, f'display name "{from_name}" matches {person["title"]} {person["name"]} but address is {from_addr}')
    if from_dom in FREEMAIL and any(p["name"].lower() in (from_name or "").lower() for p in directory):
        flag(10, "executive name on a free email service")
    brand_names = {base_label(d) for d, o in trusted.items() if o != "CORP"}
    if any(b in (from_name or "").lower().replace(" ", "") for b in brand_names) and \
            from_dom not in trusted and not look:
        flag(15, f'display name "{from_name}" uses a brand but the domain {from_dom} is not that brand')
    if "microsoft" in (from_name or "").lower() and "microsoft" not in from_dom and not look:
        flag(15, "display name says Microsoft, domain does not")

    # links
    link_report = []
    for href, visible in links:
        real = urlparse(href).hostname or ""
        shown_host = urlparse(visible).hostname if visible.startswith("http") else None
        entry = {"href": href, "text": visible, "domain": real}
        if shown_host and real and shown_host != real:
            entry["mismatch"] = f"text shows {shown_host}, link goes to {real}"
            flag(25, f"link text shows {shown_host} but points to {real}")
        if href.startswith("http://") and pw_inputs == 0 and "login" in href:
            flag(10, "login link without HTTPS")
        if lookalike_of(real, trusted):
            flag(20, f"link to lookalike domain {real}")
        if re.match(r"https?://\d+\.\d+\.\d+\.\d+", href):
            flag(15, "link to a raw IP address")
        link_report.append(entry)

    # attachments
    for a in attachments:
        if a["risky_extension"]:
            flag(20, f'risky attachment type: {a["filename"]}')
        if a.get("password_fields"):
            flag(30, f'attachment {a["filename"]} contains a password form posting to {", ".join(a["form_actions"]) or "?"}')

    # language
    hits = {cat: [w for w in words if w in text] for cat, words in LANGUAGE.items()}
    hits = {k: v for k, v in hits.items() if v}
    if len(hits) >= 2:
        flag(5 * len(hits), "social-engineering language: " + ", ".join(f"{k} ({', '.join(v)})" for k, v in hits.items()))
    if "payment" in hits and "secrecy" in hits:
        flag(15, "payment request + secrecy: business email compromise pattern")

    score = min(100, sum(p for p, _ in findings))
    verdict = "MALICIOUS" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LIKELY BENIGN"
    kind = classify(findings, attachments, verdict)

    iocs = sorted({from_addr} | ({reply_addr} if reply_addr else set())
                  | {l["domain"] for l in link_report if l["domain"] and l.get("mismatch") or lookalike_of(l["domain"], trusted)}
                  | {f for f in forms if f} | ({origin_ip(msg)} if verdict != "LIKELY BENIGN" and not (from_dom in FREEMAIL and auth["dmarc"] == "pass")
                     else set()))   # a free-mail provider's server IP is shared by millions of users: do not block it
    # never block our own domain (spoofed) or a whole free-mail provider: block addresses / URLs / IPs instead
    iocs = {i for i in iocs if domain_of(i) not in our_domains}
    if verdict == "LIKELY BENIGN":
        iocs = set()
    return {
        "file": os.path.basename(path), "subject": str(msg.get("Subject", "")),
        "from": f"{from_name} <{from_addr}>", "reply_to": reply_addr or "-", "to": str(msg.get("To", "")),
        "date": str(msg.get("Date", "")), "origin_ip": origin_ip(msg), "auth": auth,
        "links": link_report, "attachments": attachments, "findings": [w for _, w in findings],
        "points": [p for p, _ in findings], "score": score, "verdict": verdict, "type": kind,
        "iocs_defanged": [defang(i) for i in sorted(iocs) if i and i != "-"],
        "actions": RESPONSE[verdict] + RESPONSE_BY_TYPE.get(kind, []),
        "reported_by_user": str(msg.get("X-Reported-By-User", "")) or None,
    }


def classify(findings, attachments, verdict) -> str:
    text = " ".join(w for _, w in findings)
    if verdict == "LIKELY BENIGN":
        return "Legitimate / marketing"
    if "business email compromise" in text or "matches Chief" in text:
        return "Business Email Compromise (impersonation)"
    if any(a.get("password_fields") for a in attachments) or "password form" in text:
        return "Credential phishing (HTML attachment)"
    if "lookalike" in text or "link text shows" in text:
        return "Credential phishing (link)"
    return "Phishing / spoofing"


RESPONSE = {
    "MALICIOUS": ["Do not interact; thank the reporter", "Search all mailboxes for the same sender / subject / URL and purge",
                  "Block the IOCs below (sender address, URLs, IPs) at mail gateway, proxy and DNS - never our own domain or a whole free-mail provider",
                  "Check proxy / DNS logs: did anyone click or submit credentials?"],
    "SUSPICIOUS": ["Hold the message; verify with the supposed sender through a known channel",
                   "Search for similar messages before deciding"],
    "LIKELY BENIGN": ["Release / close as legitimate; explain to the reporter why (good reporting, keep it up)"],
}
RESPONSE_BY_TYPE = {
    "Credential phishing (link)": ["For anyone who clicked: reset password, revoke sessions, check sign-in logs and MFA prompts"],
    "Credential phishing (HTML attachment)": ["For anyone who opened the form: reset password, revoke sessions, check sign-in logs",
                                              "Our domain was spoofed: check DMARC policy is p=reject so receivers drop these",
                                              "Mail gateway rule: quarantine HTML attachments from external senders"],
    "Business Email Compromise (impersonation)": ["Call the executive on a known number; warn Finance",
                                                  "Add an 'external sender' banner and a display-name impersonation rule"],
}


# --------------------------------------------------------------------------- output

def print_report(r: Dict) -> None:
    print("=" * 100)
    print(f'{r["file"]}  ->  {r["verdict"]} ({r["score"]}/100)  {r["type"]}')
    print(f'Subject : {r["subject"]}')
    print(f'From    : {r["from"]}   Reply-To: {r["reply_to"]}')
    print(f'Auth    : SPF={r["auth"]["spf"]}  DKIM={r["auth"]["dkim"]}  DMARC={r["auth"]["dmarc"]}   origin IP {r["origin_ip"]}')
    for l in r["links"]:
        print(f'Link    : {defang(l["href"])}' + (f'   <-- {l["mismatch"]}' if l.get("mismatch") else ""))
    for a in r["attachments"]:
        print(f'Attach  : {a["filename"]} ({a["type"]}, {a["size"]} B) sha256={a["sha256"][:16]}...')
    if r["findings"]:
        print("Why     :")
        for p, w in zip(r["points"], r["findings"]):
            print(f"   +{p:<3} {w}")
    if r["iocs_defanged"]:
        print("IOCs    : " + ", ".join(r["iocs_defanged"]))
    print("Actions : " + " | ".join(r["actions"]))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Triage .eml files for phishing.")
    p.add_argument("files", nargs="*")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    files = a.files or sorted(os.path.join(DATA, "emails", f) for f in os.listdir(os.path.join(DATA, "emails"))
                              if f.endswith(".eml"))
    trusted = load_trusted(os.path.join(DATA, "trusted_domains.csv"))
    directory = load_directory(os.path.join(DATA, "directory.csv"))
    results = [analyze(f, trusted, directory) for f in files]
    os.makedirs(os.path.join(HERE, "output"), exist_ok=True)
    with open(os.path.join(HERE, "output", "triage_results.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(results, fh, indent=2)
    if a.json:
        json.dump(results, sys.stdout, indent=2)
        return 0
    print(f"{'FILE':<28} {'VERDICT':<14} {'SCORE':>5}  TYPE")
    for r in results:
        print(f'{r["file"]:<28} {r["verdict"]:<14} {r["score"]:>5}  {r["type"]}')
    print()
    for r in results:
        print_report(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
