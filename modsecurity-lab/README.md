# ModSecurity + OWASP CRS Lab Configuration

Place custom OWASP CRS configuration files in this directory if you need to override the default ruleset.
Using `docker-compose.waf-lab.yml`, the `owasp/modsecurity-crs` WAF binds to `127.0.0.1:8088` (offset from `:8080` to avoid colliding with Burp Suite Proxy) and forwards requests to `victim-app` on port `8081`.

## Running the Lab

```bash
docker compose -f docker-compose.waf-lab.yml up -d
```

## Testing with HunterAI

```bash
python pentest.py waf-bypass http://127.0.0.1:8088/search --payload "<svg onload=alert(1)>"
```

## Notes

- Use this lab strictly for local testing on systems you own.
- Do not target systems outside your explicit written authorization.
