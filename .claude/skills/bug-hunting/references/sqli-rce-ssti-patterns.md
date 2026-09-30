# SQL Injection, SSTI & RCE — Real Disclosed-Report Pattern Library

These are lower-frequency finds than IDOR/XSS (modern frameworks defend
against them by default) but pay the most per bug when confirmed — often
the highest tier a program offers. Drawn from disclosed HackerOne reports.

## SQL Injection

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Blind/time-based via unexpected param** | Mail.ru (H1 #732430) | Blind SQLi via an insecurely-used GET parameter on a news page — not an obvious "search" field. |
| **Injection via HTTP header, not a form field** | GSA/data.gov (H1 #297478) | SQLi confirmed via sleep-based payloads in the **User-Agent header** — always test headers (User-Agent, Referer, X-Forwarded-For), not just visible inputs. |
| **Time-based blind on DoD assets** | DoD (H1 #2759243, #313037, #2597543) | Recurring pattern: response-time manipulation via `SLEEP()`/`WAITFOR DELAY`-style payloads confirms injection even with no visible error or data returned. |
| **Injection in a secondary/forgotten subdomain** | Automattic/Atavist docs subdomain (H1 #1039315) | Found on `docs.atavist.com` — a documentation or secondary subdomain, not the main app. Don't skip "minor" subdomains during recon. |

### Fast test approach
1. Test every parameter that could plausibly touch a query: search, filter, sort, pagination, ID fields — and also headers (`User-Agent`, `Referer`, `X-Forwarded-For`, custom headers).
2. Start with a single quote `'` and observe for errors; if none, move to boolean-based (`' AND 1=1--` vs `' AND 1=2--` and compare responses) and time-based (`' AND SLEEP(5)--`, or DB-specific equivalents).
3. Confirm with `sqlmap` only once you have a parameter you suspect is vulnerable — don't blind-scan every endpoint on an in-scope target; respect rate limits and program rules about automated scanning intensity.
4. Include subdomains and secondary properties (docs, blog, forums, admin panels) in your target list — several disclosed reports above were found off the main app.

## SSTI → RCE

Server-Side Template Injection is one of the highest-value chains: find
it, and it often goes straight to remote code execution.

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Jinja2 (Flask) SSTI → RCE** | Uber (H1 #125980, $10,000) | Classic `{{7*7}}`-style probe confirmed Jinja2 template injection, escalated to full RCE. Still one of the highest-value single-bug categories when found. |
| **Smarty template SSTI → RCE** | Unikrn (H1 #164224) | Same pattern, different template engine — test engine-specific syntax once you suspect templating (Smarty uses `{$smarty.version}` style probes). |
| **Handlebars SSTI → RCE** | Shopify (H1 #423541) | Handlebars is normally considered "logicless" and SSTI-resistant — this report shows that assumption can still fail depending on how it's invoked server-side. Don't skip testing an engine just because it's marketed as safe. |
| **EJS via view-rendering plugin** | Fastify (H1 #3122019) | `@fastify/view` + EJS allowed arbitrary EJS execution → RCE when an attacker could control raw content passed to the renderer — look for any feature where user input reaches a template-rendering call, even indirectly (e.g. via a plugin/middleware layer). |
| **lodash `_.template` SSTI** | H1 #904672 | Even a utility function not marketed as a "template engine" (`lodash.template`) can be SSTI-vulnerable if user input reaches it — check JS-based backends for any `_.template`, `eval`, or dynamic `Function()` construction fed by user data. |

### Fast test approach
1. Identify any feature that looks like it renders user-supplied content into a template: email templates, PDF generation, report generation, "customize your page" features, notification templates.
2. Probe with engine-agnostic math: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}` — if any renders as `49` instead of literal text, you likely have SSTI.
3. Identify the specific engine from the probe syntax that worked, then use engine-specific RCE payloads (Jinja2: `{{ self.__init__.__globals__... }}` chains; Smarty: `{system('id')}`-style; consult `tplmap` for automated engine fingerprinting + exploitation).
4. Confirm RCE with a non-destructive command first (`id`, `whoami`, `sleep 5` as a blind-RCE confirmation) before anything further — and stop there; don't escalate beyond confirming impact on an authorized target.

## General RCE (non-SSTI)

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Unsafe deserialization / JNDI injection** | Acronis forum (H1 #1430622) | JNDI-style code injection (Log4Shell-family pattern) via a forum feature — check any Java-based backend for JNDI lookup injection in logged user input. |
| **RCE via game client** | Valve/Portal 2 (H1 #733267) | RCE wasn't in a web app at all — it was in a game client's handling of a crafted file/input. Reminder: "web" bug bounty programs sometimes include desktop/client software in scope — check the scope page carefully. |
| **Command execution via OS-level integration** | MTN Group (H1 #810755) | Remote OS command execution, likely via a feature that shells out to the OS (image processing, file conversion, etc.) — any "upload and process a file" feature deserves a check for command-injection-via-filename or command-injection-via-file-content. |

### Fast test approach for general RCE
1. Look for features that shell out to the OS: image/video conversion, PDF generation from HTML, file format conversion, thumbnail generation.
2. Test filenames and file content for command-injection characters (`; `, `|`, `` ` ``, `$()`) if the app might pass them to a shell command.
3. For Java backends: check if user input (including odd places like User-Agent, X-Forwarded-For) ends up in a logged string that could trigger JNDI lookup-style injection.
4. Always confirm with the least invasive proof possible (`sleep`, `id`, a harmless file write to a location you can verify) — full RCE findings carry legal and ethical weight; never pivot beyond what's needed to prove the vulnerability, and never touch data beyond what's required for the PoC.
