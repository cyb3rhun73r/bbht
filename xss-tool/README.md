# XSS Tool (scope-gated, single-target)

A small pipeline for authorized bug bounty XSS testing:

1. **`scope_validator.py`** — checks a target URL against a program's
   published scope (in-scope / out-of-scope patterns you copy from the
   program page). Nothing downstream runs unless this passes.
2. **`xss_scanner.py`** — crawls exactly one target that already passed
   the scope check, tests reflected XSS via query params and GET forms,
   flags potential DOM XSS sinks via static analysis, and assigns a
   confidence level (High/Medium/Low) to each finding.
3. **`report_generator.py`** — turns scan results into a submission-ready
   Markdown report.
4. **`bbht_xss.py`** — orchestrates all three in one command.

## What this tool deliberately does NOT do

- It does not discover or choose targets for you (no dorking, no
  scraping bug bounty platforms for "open" programs). You supply one
  target you are already registered/authorized to test.
- It will not send a single request until the target has passed the
  scope check AND you've passed `--confirm-authorized`, an explicit
  attestation that you're allowed to test that target under the
  program's rules.
- All requests are rate-limited (`--delay`, default 0.5s) and capped in
  crawl breadth (`--max-pages`, default 25) to stay well clear of
  anything resembling mass/DoS-style traffic.
- Findings are heuristic. Confidence levels tell you how much manual
  verification is still needed before you submit — they are not proof
  of exploitability.

## Usage

```bash
pip install -r requirements.txt

# 1. Build a scope file from the program's published scope
cp example_scope.json my_program_scope.json
# edit my_program_scope.json with the real in-scope/out-of-scope patterns

# 2. Run the full pipeline against ONE target you're authorized to test
python bbht_xss.py \
  --scope my_program_scope.json \
  --target https://app.example.com/search?q=test \
  --confirm-authorized

# Outputs: scan_result.json, report.md
```

Or run each stage independently:

```bash
python scope_validator.py --scope my_program_scope.json --target https://app.example.com/
python xss_scanner.py --scope my_program_scope.json --target https://app.example.com/ --confirm-authorized
python report_generator.py --result scan_result.json --out report.md
```

## Scope file format

```json
{
  "program": "Example Corp Bug Bounty",
  "in_scope": ["app.example.com", "*.example.com"],
  "out_of_scope": ["blog.example.com", "app.example.com/logout"]
}
```

Wildcards (`*`) are supported for subdomains and path prefixes.
Out-of-scope patterns always win over in-scope ones.
