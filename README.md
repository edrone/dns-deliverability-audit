# DNS Deliverability Audit

Claude Code skill that audits email deliverability DNS configuration (SPF, DKIM, DMARC) for a list of edrone client domains. Designed for diagnosing high bounce rates on Hotmail/Outlook, where Microsoft has been hard-rejecting (5.7.515) mail with broken DMARC since November 2025.

## What it does

For each domain, runs DNS queries via `dig` and detects 12 common breakages:

| Check | Severity | Why it matters |
|---|---|---|
| Multiple SPF records | RED | RFC 7208 → permerror, SPF effectively absent |
| Multiple DMARC records | RED | RFC 7489 → ignored, DMARC=None → Microsoft 5.7.515 |
| SPF missing | RED | Mail from edrone fails alignment |
| SPF ending in `?all` (NEUTRAL) | YELLOW | Outlook penalizes; should be `~all` or `-all` |
| Zero-width Unicode (U+200B) in SPF | RED | Copy-paste from Word/Notion silently breaks SPF |
| Typo includes (e.g. `include:hostinger`) | YELLOW | Silent fail of that include |
| DMARC `rua` missing `mailto:` prefix | YELLOW | Reports never sent |
| DMARC `rua` cross-domain w/o `_report._dmarc` auth | YELLOW | Gmail/MS refuse to send reports |
| DMARC `rua` target domain has no MX/A | YELLOW | Reports bounce |
| DMARC syntax errors (`;+p=` etc) | YELLOW | Some parsers ignore |
| DKIM edrone selector missing | RED | Onboarding incomplete |
| DKIM `google._domainkey` missing AND MX is Google | YELLOW | Workspace support mail fails DMARC |

## Pattern in BR market

Based on audits of 20+ active edrone clients, **~65% of BR domains have duplicate SPF or DMARC** because each platform (Locaweb, Hostinger, Tray, Zendesk, edrone) added its own DNS record without anyone cleaning up. This is the root cause of most Hotmail bounce issues in BR — not bad content, not bad reputation, just RFC-incompliant DNS.

## Outputs

- **Console** — severity table with per-domain breakdown
- **`~/Desktop/dns-audit-YYYY-MM-DD.xlsx`** — full audit report with current state and recommended fixes
- **`~/Desktop/dns-audit-YYYY-MM-DD-recommendations.csv`** — CSV with same data for spreadsheet workflows
- **`~/Desktop/dns-audit-YYYY-MM-DD-memos/`** — PT-BR remediation memos, one per RED client, ready for the BR CSM team to forward to clients

## Installation

```bash
git clone https://github.com/edrone/dns-deliverability-audit.git ~/.claude/skills/br-dns-deliverability-audit
```

That's it. Claude Code picks it up automatically and triggers on relevant phrases.

### Requirements

- `dig` — ships with macOS, available via `bind-utils` on Linux
- `python3` — 3.9+
- `openpyxl` — `pip3 install openpyxl` (only required if you want xlsx output)

## Usage

### From a SparkPost bounce CSV

```bash
python3 ~/.claude/skills/br-dns-deliverability-audit/audit_dns.py \
  --csv ~/Downloads/sparkpost-csv-XXXXXX.csv \
  --top 20
```

`--top N` audits the N domains with the highest bounce counts.

### From a list of domains

```bash
python3 ~/.claude/skills/br-dns-deliverability-audit/audit_dns.py \
  --domains pijamaswaleju.com.br uniaovegetal.com.br prohair.com.vc
```

### Via Claude Code

Just ask in natural language:

- *"audyt deliverability dla klientów BR"*
- *"sprawdź czemu klienci mają bounce na Hotmail"*
- *"audit DKIM/SPF/DMARC dla tej listy"*
- *"/audit-dns"*

Claude auto-triggers the skill, runs the script, and summarizes the findings.

## Example output

```
====================================================================================================
  # Domain                              Bounces  SPF  DMARC  eDKIM  gDKIM Severity
====================================================================================================
  1 pijamaswaleju.com.br                 63,461    1      1      ✓      — 🔴 RED
  2 uniaovegetal.com.br                  38,983   2!     2!      ✓      — 🔴🔴 DOUBLE-RED
  3 gatza.com.br                         36,659    1      1      ✓      — 🔴 RED
  4 prohair.com.vc                       31,352   2!     4!      ✓      — 🔴🔴 DOUBLE-RED
  ...

  Total: 20 domains  |  🟢 3  🟡 1  🔴 13  🔴🔴 3
```

The xlsx columns: `domain | bounces | severity | spf_count | dmarc_count | dkim_edrone | dkim_workspace | mx_provider | issues | recommended_spf | recommended_dmarc | raw_spf | raw_dmarc`.

## How the memos read

Each PT-BR memo (one per RED domain) contains:
1. **Severity** + bounce count + MX provider
2. **Problems identified** — translated from internal labels to client-friendly PT-BR
3. **Current DNS state** — raw SPF/DMARC records as they exist today
4. **Recommended fixes** — exact records to paste into DNS, plus SNDS/JMRP registration links

The CSM team can forward these to clients with minimal editing.

## Related tools

- **edrone Hermes skill:** `cs-dns-deliverability-audit` (mirror of this skill, callable via Hermes)
- **SparkPost** — source of bounce data
- **Microsoft SNDS / JMRP** — IP reputation and feedback loops
  - SNDS: https://sendersupport.olc.protection.outlook.com/snds/
  - JMRP: https://sendersupport.olc.protection.outlook.com/snds/JMRP.aspx

## License

Internal use — edrone Sp. z o.o.
