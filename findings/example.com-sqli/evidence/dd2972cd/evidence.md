# Evidence Bundle — sqli

**Target:** example.com
**Bundle ID:** dd2972cd
**Generated:** 2026-10-18 15:47:48

## Request
```http
GET https://example.com/search?q=test HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Authorization: Bearer sk-abcdef1234567890


```

## Response
```http
HTTP/1.1 200 OK
Content-Type: text/html
Server: nginx

<html>Search results for: test</html>
```

## Reproduction
```bash
curl -X GET 'https://example.com/search?q=test'
```

## Evidence Hash
SHA-256 of response: `b1025575c5efee80...`

**Secrets redacted by default.**
