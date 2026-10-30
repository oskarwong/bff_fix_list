I'll start by pulling the text out of the report so I can scan all 165 pages, and look at the repo structure alongside.

The scan found 8 vulnerabilities (3 High, 5 Low), plus 4 Info and 1 Best Practice. Most of the 165 pages just list checks that passed. Next I'll pull out the failed checks and the detail sections.

That gives 13 failed checks. The detailed findings (URLs, requests, responses) should come after the check list, so I'll read that part.

The appendix should say which ciphers were flagged and why each check failed. I'll read that next.

I have all 13 failed checks. Now I'll map them to the code: the Express/Apollo setup, the header middleware, the error handling, and any nginx config in the repo.

Routes are mounted at `/` in the app, so `/care-bff/v0/` must be rewritten by an ingress. I'll check the K8s and deploy files for nginx annotations, TLS, and headers.

The flagged "Unhandled Exception" is actually from a normal 200 response on `getCoverBanners`, where the scanner misread a `/tc/home/campaign/...` link as a Unix path. I'll inspect the banner data to confirm this is a false positive.

I noticed multiple routes registering on `/` and a 3-argument error middleware at the end of `index.ts`. Next, I'll check the `NODE_ENV` setting, how `getAccountProfile` identifies users, whether the 50mb body limit is necessary, and which ingress manifest is actually live.

Both Dockerfiles set NODE_ENV=production, so Express won't leak stack traces, and getAccountProfile pulls the user from the JWT rather than an argument. Next I'll check whether getAuthorization actually verifies the JWT signature.

Signature verification checks out—the response is just the caller's own data from the token, not an IDOR. Before suggesting a GraphQL alias-limit fix, I'll test it against the scanner's exact payload.

The scan found **13 failed checks**. Only one is a real High (weak TLS ciphers). The other two Highs are false positives or by design, and the rest are Low or Info. Everything except two Info/Low checks hits one endpoint, the GraphQL endpoint **`POST https://care-api.smartone.com/care-bff/v0/`**.

## Failed checks

| Severity | Check (ID) | Operation | Verdict | Fix location |
|---|---|---|---|---|
| **High** | Weak SSL Cipher (11285) | any request | **Real** | nginx ingress TLS config |
| High | Email Disclosure (11578) | `getAccountProfile` | By design | Accept / document it |
| High | Privacy Violation (11577) | `getMaster` | False positive | Accept / document it |
| Low | Denial of Service: GraphQL (11747) | aliased query batch | **Real** | `index.ts` |
| Low | Insecure Content-Type, no `nosniff` (11309) | `getAccountProfile` | **Real** | `index.ts` |
| Low | HSTS not set (11365) | `getAccountProfile` | **Real** | `index.ts` or ingress |
| Low | XSS Protection header (11603) | `OPTIONS /` | Real (scanner rule) | `index.ts` |
| Low | Unhandled Exception (810) | `getCoverBanners` | Almost certainly false positive | Accept |
| Info | Known Technology Fingerprint, TLS_RSA ciphers (11571) | — | Real | Same fix as 11285 |
| Info | OPTIONS method (10282) | `OPTIONS /` | Expected | Leave it |
| Info | Cache Management: Headers (10302) | — | Expected (`Vary: Origin` comes from `cors`) | Leave it |
| Info | Missing PQC key exchange (11770) | — | Future work | Later |
| BP | Missing Perfect Forward Secrecy (11364) | — | Real | Same fix as 11285 |

## 1. TLS ciphers (fixes 11285, 11571 and 11364 together)
The server offers CBC and `TLS_RSA_*` ciphers (8 of the offered ciphers have no forward secrecy). TLS ends at the NGINX Inc ingress (`nginx.org/*` annotations in `K8s-prod.yaml`, `Server: nginx/1.25.5`). The cipher setting lives in the ingress controller's ConfigMap, which is not in this repo. Changing it affects every host on that controller, so the platform team needs to do it:
```yaml
ssl-protocols: "TLSv1.2 TLSv1.3"
ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
server-tokens: "false"   # also hides the nginx/1.25.5 version
```
If a CDN or load balancer sits in front and ends TLS there, apply the change at that layer instead. Removing the RSA key-exchange ciphers can break very old client devices, so check client stats before rollout.

## 2. Security headers (fixes 11309, 11365, 11603)
Add this right after `const app = express();` (`index.ts:80`):
```ts
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});
```
- `X-XSS-Protection` is a deprecated header and does nothing for a JSON API. Setting it only satisfies this scanner rule.
- `app.disable('x-powered-by')` removes the `X-Powered-By: Express` header that every response shows.
- HSTS could instead be set with the `nginx.org/hsts` annotation on the ingress.

## 3. GraphQL alias batching (11747)
The scanner sent one query with 11 aliases (`wi0`…`wi10`) and got 11 separate errors back. That shows the server processes unlimited aliases in one request. Apollo's array batching is off by default and not enabled here, so aliases are the gap.

Add this between `bodyParser.json` and `expressMiddleware` (`index.ts:360-368`):
```ts
import { parse, visit } from 'graphql';
const MAX_ALIASES = 10;

function rejectAliasBatching(req, res, next) {
  const query = req.body?.query;
  if (typeof query === 'string') {
    try {
      let aliases = 0;
      visit(parse(query), { Field(node) { if (node.alias) aliases++; } });
      if (aliases > MAX_ALIASES) {
        return res.status(400).json({ errors: [{ message: 'TOO_MANY_ALIASES', extensions: { code: 'GRAPHQL_VALIDATION_FAILED' } }] });
      }
    } catch { /* syntax error: let Apollo return its normal error */ }
  }
  next();
}
```
- I tested the counting logic against the scanner's exact payload: it rejects that payload and lets normal queries through. I did not run it inside the app.
- I used a pre-check instead of Apollo's `validationRules` because a validation rule runs next to the built-in rules. The response would still contain the 11 per-alias errors the scanner looks for.
- Set `MAX_ALIASES` above the largest query your apps really send.
- The 50 MB JSON body limit is also very high for a DoS target. I found no upload or base64 fields in `schemas/`, so you could probably lower it.

## 4. Findings to mark as false positive or accepted
- **Email Disclosure (11578):** `getAccountProfile` returns the logged-in user's own email. The user comes from the verified JWT (`resolvers/v0/acct.ts:25`, `jwt.verify` with the RSA key in `functions/v0/function.ts:262`), and the response has `cache-control: no-store`. This is not an IDOR.
- **Privacy Violation (11577):** the matched words ("date of birth", "gender") are in the privacy-policy text inside the 1.1 MB `getMaster` response. That is document text, not user data.
- **Unhandled Exception (810):** the response was a normal 200 from `getCoverBanners`. The highlighted part is a banner link `https://www.smartone.com/tc/home/campaign/...`, and `/home/...` looks like a Unix home folder to the scanner. Stack traces are already off (`includeStacktraceInErrorResponses: false`, `NODE_ENV=production`). Confirm in WebInspect's response view, then mark it false positive.
- **OPTIONS (10282):** this is Express's automatic reply on `/` (the 13-byte body matches `GET,HEAD,POST`). Don't block OPTIONS at nginx, because browser CORS preflight from `care.smartone.com` needs it.
- **PQC (11770):** this needs an nginx built with OpenSSL 3.5+ (X25519MLKEM768 key exchange). Treat it as a roadmap item, not a fix for now.

One note about the PDF: it includes a test account's personal data and a bearer token. The token expired on 28 Oct, but share the report carefully.

I can make the `index.ts` changes from sections 2 and 3 on a branch, or turn this into a page you can share with the security or platform team.
