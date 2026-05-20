---
name: br-dns-deliverability-audit
description: >
  Audit email deliverability DNS configuration (SPF, DKIM, DMARC) for a list of edrone client domains —
  designed for diagnosing high bounce rates, especially on Hotmail/Outlook (Microsoft 5.7.515 errors).
  Use this skill whenever the user wants to:
  check why clients have bounces on Hotmail, audit DKIM/SPF/DMARC for multiple domains,
  diagnose deliverability issues, run a "DNS audit" or "deliverability audit",
  check for duplicate SPF/DMARC records, validate DMARC rua configuration,
  or whenever the user pastes a SparkPost CSV with sending_domain/count_bounce columns.
  Polish triggers: "sprawdź konfigurację DNS klientów", "audyt deliverability",
  "sprawdź czemu klienci mają bounce na Hotmail", "audit DKIM dla listy domen",
  "/audit-br-dns", "/audit-dns".
  Produces an Excel (.xlsx) audit report on Desktop plus per-client PT-BR remediation memos
  for the worst offenders. Works for BR/PL/any market — domain TLD is not a constraint.
---

# DNS Deliverability Audit (edrone clients)

Audits SPF / DKIM / DMARC configuration for a list of sender domains and produces:
1. A console summary table with severity per domain
2. An `.xlsx` report on Desktop
3. PT-BR remediation memos for RED domains (in a `memos/` subfolder)

## When to trigger

Trigger on any of these patterns:
- User pastes a path to a SparkPost CSV (`sparkpost-csv-*.csv` typically in Downloads)
- User pastes a list of domains and asks to "audit", "sprawdź", "check DNS/SPF/DMARC"
- User asks "czemu klient X ma bounce na Hotmail" — single-domain audit
- User says "/audit-br-dns", "/audit-dns", "audyt deliverability"

If the user asks about a **single domain**, you can still use the script (`--domains domain.com`) — it'll produce a one-row report and skip the xlsx (just print the summary).

## Why this matters

Microsoft, since November 2025, hard-rejects (5xx, no retry) mail when DMARC validation fails — including when there are **multiple DMARC records** (RFC 7489 says: ignore them all → DMARC=None → 5.7.515 from Outlook).

In the BR market specifically, **65% of audited clients have duplicate SPF or DMARC** because each platform (Locaweb, Hostinger, Tray, Zendesk, edrone) added its own record without anyone cleaning up. This is *the* root cause of most Hotmail bounce issues in BR.

The audit detects this and other common breakages and outputs ready-to-paste DNS fixes.

## How to run

The skill includes `audit_dns.py` — a self-contained Python script that does everything.

### From a SparkPost CSV

```bash
python3 ~/.claude/skills/br-dns-deliverability-audit/audit_dns.py \
  --csv "/Users/admin/Downloads/sparkpost-csv-XXXXXX.csv" \
  --top 20
```

`--top N` limits to the top N domains by bounce count (default: all rows).

### From a list of domains (no CSV)

```bash
python3 ~/.claude/skills/br-dns-deliverability-audit/audit_dns.py \
  --domains pijamaswaleju.com.br uniaovegetal.com.br prohair.com.vc
```

### Outputs

- Console: severity table (GREEN/YELLOW/RED/DOUBLE-RED) with issue counts
- `~/Desktop/dns-audit-YYYY-MM-DD.xlsx` — full report with columns:
  `domain | bounces | spf_count | dmarc_count | dkim_edrone | dkim_workspace | mx_provider | severity | issues | recommended_spf | recommended_dmarc`
- `~/Desktop/dns-audit-YYYY-MM-DD-memos/` — one `.md` file per RED/DOUBLE-RED client, PT-BR, ready to forward via CSM

## What the script detects

| Check | Severity | Notes |
|---|---|---|
| Multiple SPF records | 🔴 RED | RFC 7208 → permerror, SPF effectively absent |
| Multiple DMARC records | 🔴 RED | RFC 7489 → ignored, DMARC=None → Microsoft 5.7.515 |
| SPF missing entirely | 🔴 RED | Common for `.com.br` migrated to edrone-only |
| SPF ending in `?all` (NEUTRAL) | 🟡 YELLOW | Outlook penalizes; should be `~all` or `-all` |
| Zero-width Unicode in SPF (U+200B) | 🔴 RED | Copy-paste from Word/Notion silently breaks SPF |
| Typo includes (e.g. `include:hostinger` w/o TLD) | 🟡 YELLOW | Silent fail of that include |
| DMARC `rua` missing `mailto:` prefix | 🟡 YELLOW | Reports never sent |
| DMARC `rua` cross-domain w/o `_report._dmarc` auth | 🟡 YELLOW | Gmail/MS refuse to send reports |
| DMARC `rua` target domain has no MX/A | 🟡 YELLOW | Reports bounce |
| DMARC syntax errors (`;+p=` etc) | 🟡 YELLOW | Some parsers ignore |
| DKIM edrone selector missing | 🔴 RED | Means edrone wasn't fully onboarded |
| DKIM `google._domainkey` missing AND MX is Google | 🟡 YELLOW | Workspace support mail fails DMARC |

**Severity stacking:** 1 yellow = YELLOW, 2+ yellow = RED, 1+ red = RED, 2+ red = DOUBLE-RED.

## What the memos contain

Each PT-BR memo (one per RED domain) has:
1. The exact problems found, with explanation
2. The exact DNS records to apply (single SPF, single DMARC, etc.)
3. Instructions to register the domain in Microsoft SNDS + JMRP
4. Footer with the BR CSM contact line

The user can forward these directly to clients (typically via the CSM team in BR).

## Interpretation guidance

After running the script, present to the user:
1. A compact summary table (top 10 by bounce volume)
2. The total breakdown: `X red, Y yellow, Z green` out of N domains
3. Highlight the worst offenders by name and what specifically is wrong (1-2 sentences each)
4. Point at the .xlsx and memos folder paths
5. Offer next actions: send memos via CSM, register clients in SNDS/JMRP, re-run after 24-48h

If only a small number of domains, you can show full results inline instead of just the top 10.

## Edge cases

- **Single-domain query**: run with `--domains X` and just summarize verbally — no need to open xlsx
- **CSV with weird encoding**: the script handles UTF-8 with BOM; if it fails, fall back to manual `dig` checks
- **dig not installed**: warn the user (rare on macOS — `dig` ships with the OS)
- **Slow networks**: the script queries DNS sequentially with a 5s timeout per query, ~6 queries per domain → ~30s/domain worst case. For 20 domains, expect 1-3 minutes.

## Why a script and not pure SKILL.md instructions

The DNS parsing logic is intricate enough (zero-width chars, syntax variants, severity matrix, record merging) that doing it inline would (a) burn tokens and (b) produce inconsistent results across runs. The script makes the audit deterministic — same input always produces the same xlsx. SKILL.md just orchestrates the run and interprets the output.
