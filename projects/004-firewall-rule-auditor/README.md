# 004 · Firewall Rule Auditor

▶ **Watch the 30-second demo:** [demo.mp4](demo.mp4)

**Category:** Security · **Language:** Python 3.11+ (standard library only)

Finds **shadowed, redundant and conflicting rules** in a first-match firewall rule set (ACLs, security groups, iptables-style chains). Each rule is treated as a box in a 4-dimensional packet space, *protocol × source × destination × port*, and every pair of rules is compared with exact set logic. A finding is therefore a proof, not a guess: if the tool says a rule can never fire, there is no packet that would reach it.

## Why it matters

Rule sets only grow. After a few years of tickets, an `allow` you added for a new service can sit *below* a broad `deny` and silently never match. The service is down, the rule "looks right" in review, and nobody knows why. The reverse is worse: a broad early `allow` can quietly defeat a later `deny` you thought was protecting something. Catching these before deployment is cheap; debugging them in production is not.

## How it works

1. **Parse** each line `<allow|deny> <tcp|udp|any> <src CIDR|any> <dst CIDR|any> <port|lo-hi|any>`. CIDRs become integer intervals (`ipaddress`), ports become `[lo, hi]`, `any` becomes the full range.
2. **Compare every earlier rule A with every later rule B** (first match wins):

   | Finding | Condition | Severity |
   |---|---|---|
   | `SHADOWED` | A covers B completely, opposite action → B never fires | error |
   | `REDUNDANT` | A covers B completely, same action → B is dead weight | warning |
   | `CONFLICT` | A and B partially overlap, opposite actions → order decides | info |
   | `GENERALIZATION` | B is a broader opposite rule (e.g. default deny); shown with `--all` | info |

   "Covers" means containment on all four dimensions; "overlap" means a non-empty intersection on all four.
3. **Skip dead rules** so a rule that can never fire doesn't produce follow-up noise.
4. **Report** and exit with `1` if any `error` was found (handy in CI), `2` on a parse error, `0` otherwise.

## How to run

```bash
python fw_auditor.py examples/rules.txt
python fw_auditor.py examples/rules.txt --json   # machine-readable
python fw_auditor.py examples/rules.txt --all    # include GENERALIZATION
python -m pytest -q                              # run the tests
```

## Example output

```text
$ python fw_auditor.py examples/rules.txt
Audited 8 rules, 4 findings
  [SHADOWED      ] line  5: allow tcp 10.0.5.0/24 10.0.2.0/24 5432
                   -> never matches; line 4 already denies all its traffic
  [REDUNDANT     ] line  6: allow tcp any 10.0.1.10/32 443
                   -> never matches; already covered by line 2 (same action)
  [CONFLICT      ] line  7: deny any 192.168.0.0/16 10.0.1.0/24 any
                   -> partially overlaps line 2 with the opposite action
  [CONFLICT      ] line  8: allow udp any any 53
                   -> partially overlaps line 7 with the opposite action
Result: FAIL (1 error(s))
```

The `SHADOWED` finding is the classic bug: the app servers' Postgres rule sits below the DB-tier lockdown, so it never matches. The first `CONFLICT` shows that the "block legacy LAN" rule does **not** block HTTPS from that LAN to the web tier, because line 2 already allowed it.

## Limitations & ideas

- Pairwise analysis: a rule covered only by the *union* of several earlier rules isn't flagged. Next step: encode rules as Z3 bit-vector constraints and ask the solver whether any packet can still reach each rule.
- IPv4, TCP/UDP and destination ports only; no source ports, ICMP types, interfaces or stateful matches.
- Ideas: importers for `iptables-save`, AWS security groups and nftables; a "suggested reorder" mode; SARIF output for code-scanning dashboards.
