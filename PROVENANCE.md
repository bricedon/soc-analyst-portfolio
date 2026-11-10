# Provenance: who did what

I use AI as a coding and teaching assistant. This page keeps the line between **what the AI prepared**, **what I ran and verified**, and **what I improved myself** clear and honest. I update it as I work through each lab.

**Rule I follow:** a line goes in "Executed" or "Improved" only if I did it and can show the output, the commit, or the report.

| Lab | Prepared with AI assistance (Claude) | Executed & verified by me | Improved by me |
|---|---|---|---|
| 01 SOC Detection & IR | Log generator, 3 scenarios, detection + scoring, timelines, SPL, 15 tests, docs, exercise | _date · command · result_ | _e.g. wrote INC-0001; validated SPL in Splunk Free; added low-and-slow rule_ |
| 02 CloudTrail & IAM | CloudTrail generator, identity-chain resolver, ticket matching, 9 tests, guide, exercise | | |
| 03 Vulnerability Prioritization | Data, scoring model, register, ticket, revalidation, 7 tests, method doc, exercise | | |
| 04 Phishing Triage | 5 sample emails, triage tool, 10 tests, exercise | | |
| 05 Network Beaconing | conn-log generator, beacon scoring, 7 tests, exercise | | |
| 06 Linux SSH Investigation | auth.log generator, parser + rules, 6 tests, response table, exercise | | |
| 07 CMMC L1 Gap Assessment | Requirement set, sample assessment, planner, 7 tests, exercise | | |
| 08 Endpoint Process Detection | Sysmon generator, 6 rules, allowlist, process tree, 3 Sigma rules, 8 tests, exercise | | |

### Verification done when the labs were built (build environment, Python 3.13 on Linux)
- All 69 unit tests passed.
- Sigma rules parsed and converted to Splunk SPL with pySigma 2.1.
- Not executed: Splunk queries (lab 01), Athena SQL (lab 02), AWS CLI response commands (lab 02), Linux response commands (lab 06).
