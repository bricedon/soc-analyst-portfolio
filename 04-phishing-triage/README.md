# 04 · Phishing Email Triage Lab

> **Recruiter summary.** A triage tool that reads raw `.eml` files, the way a SOC analyst handles the "Report phishing" queue. For each email it checks **SPF / DKIM / DMARC**, display-name impersonation of executives, **Reply-To mismatch**, **lookalike domains** (`micros0ft`), links whose text and destination differ, **HTML attachments with password forms**, and social-engineering language. It returns a scored verdict, **defanged IOCs** and the response steps. The sample set includes a legitimate invoice, a credential-phishing link, a **CEO gift-card BEC that passes SPF/DKIM/DMARC**, a spoof of our own domain with an HTML credential form, and a user-reported newsletter that is actually fine.
>
> **Roles:** SOC Analyst · Email Security · Incident Response · Security Awareness
> **Stack:** Python 3 standard library (`email`, `html.parser`) · MITRE ATT&CK T1566.001/.002, T1656 (impersonation)

| Evidence | Link |
|---|---|
| Sample emails (synthetic) | [data/emails/](data/emails) |
| Triage results (JSON) | [output/triage_results.json](output/triage_results.json) |
| Tests (10) | [test_phishing_lab.py](test_phishing_lab.py) |

## ▶️ 3-minute demo
```powershell
cd soc-analyst-portfolio\04-phishing-triage
python triage_email.py                                    # 5 emails: 3 malicious, 2 benign
python triage_email.py data\emails\E3-ceo-gift-cards.eml  # the BEC that passes authentication
python -m unittest
```
Talking points: **(1)** E3 passes SPF, DKIM and DMARC because it really comes from Gmail. Authentication proves *who sent it*, not *that it is safe*. **(2)** E4 claims to come from our help desk, but DMARC fails and the attachment is a password form posting to an IP address. **(3)** The tool never proposes blocking our own domain, a whole free-mail provider, or Gmail's server IP. Blocking the wrong IOC creates its own incident. **(4)** E5 was reported by a user, but it is a legitimate newsletter. Thank the user, close it, and explain why.

## Example output
```text
FILE                         VERDICT        SCORE  TYPE
E1-vendor-invoice.eml        LIKELY BENIGN      0  Legitimate / marketing
E2-m365-password.eml         MALICIOUS        100  Credential phishing (link)
E3-ceo-gift-cards.eml        MALICIOUS         85  Business Email Compromise (impersonation)
E4-helpdesk-reset.eml        MALICIOUS        100  Credential phishing (HTML attachment)
E5-newsletter-reported.eml   LIKELY BENIGN      0  Legitimate / marketing

E2-m365-password.eml  ->  MALICIOUS (100/100)  Credential phishing (link)
Link    : hxxp://micros0ft-account[.]example/owa/login[.]php?u=devon[.]price   <-- text shows login.microsoftonline.com, link goes to micros0ft-account.example
   +30  lookalike domain: micros0ft-account.example imitates microsoft.com
   +15  Reply-To (support@account-verify.example) differs from From (no-reply@micros0ft-account.example)
   +25  link text shows login.microsoftonline.com but points to micros0ft-account.example
```

## Limits (honest)
Rule-based scoring on 5 samples. It does not detonate URLs or attachments, check reputation feeds, or read images (QR-code phishing). In production these checks come from the mail gateway, a sandbox and threat intelligence; this tool shows the reasoning an analyst applies on top.

## What was tested
✅ `triage_email.py` and 10 unit tests executed (Python 3.13). All emails, domains (`.example`) and people are fictional.
