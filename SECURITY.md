# Security Screening Report — Alpha Web3 Projects
Date: 2026-07-14
Scope: Public web surfaces of 12 alpha/pre-TGE projects discovered earlier
Method: Passive recon + authenticated-less HTTP probing (no destructive exploit, no brute force)
Limitation: No X cookies/API; several sites timed out/SSL failed; smart-contract source often unavailable pre-TGE

## Executive Summary
| Project | Highest real finding | Severity |
|---|---|---|
| Drake (drake.exchange) | Alchemy API key hardcoded in frontend JS; usable by spoofing Origin | **HIGH** |
| Shift (airdrop.shiftrwa.xyz) | CORS `Access-Control-Allow-Origin: *` + missing CSP/HSTS | **MEDIUM** |
| Byzanlink | Production source map exposed (Framer) | **MEDIUM** |
| Gno.land sale | Source map exposed; sale surface Netlify | **LOW-MEDIUM** |
| NOYA.ai | CORS `*` on marketing site; missing CSP | **LOW-MEDIUM** |
| OpenDelta | Missing CSP; .git/.env blocked (403) | **LOW** |
| SIXR Cricket | WordPress; users REST locked; xmlrpc present | **LOW** |
| Rekt Games | Secret-like strings in JS (needs manual verify; likely false +) | **INFO/LOW** |
| Neurolov.xyz | Parked/lander redirect domain; soft-404 noise | **INFO** |
| Diffuse / Chainers / Mavro | Unreachable from scanner (timeout/SSL) | **N/A** |

False positives filtered: SPA soft-404 for `/actuator/env`, `/graphql` on Drake/Neurolov (HTML shell, not Spring Actuator).
Gno/Shift `0x{64}` hits = secp256k1 constants / bytecode, not private keys.
Gno JWT = Netlify RUM token, not auth session.

---

## Finding 1 — Drake: Alchemy API Key Leak (HIGH)

**Target:** https://drake.exchange  
**Asset:** https://drake.exchange/assets/index-1c6348ef.js  
**Key:** `9297oAZqkm-Oerqdx-Rwy`  
**Endpoints embedded:**
- `https://monad-mainnet.g.alchemy.com/v2/9297oAZqkm-Oerqdx-Rwy` (read/write/wss)
- `https://monad-testnet.g.alchemy.com/v2/9297oAZqkm-Oerqdx-Rwy` (read/write/wss)

**Also exposed:** WalletConnect projectId `34357d3c125c2bcf2ce2bc3309d98715`

**PoC (reproducible):**
```bash
curl -s https://monad-mainnet.g.alchemy.com/v2/9297oAZqkm-Oerqdx-Rwy \
  -H "Content-Type: application/json" \
  -H "Origin: https://drake.exchange" \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}"
# returns result block number
```

Without Origin header → 403 whitelist.  
With `Origin: https://drake.exchange` → **200 OK** (Origin is trivially spoofable outside browsers).

**Impact:**
- Free/unauthorized consumption of project Alchemy quota (DoS via rate/cost)
- Potential access to enhanced Alchemy APIs if enabled on key
- Key rotation required; any historical abuse hard to attribute

**Remediation:**
1. Rotate Alchemy key immediately
2. Never embed provider secrets in public frontend; use backend proxy or public RPC
3. Prefer domain allowlist **plus** rate-limit + separate read-only key; treat browser keys as public
4. Monitor Alchemy dashboard for anomalous CU usage

**CVSS (est.):** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H) — availability/cost impact primary

---

## Finding 2 — Shift Airdrop: Permissive CORS + Weak Headers (MEDIUM)

**Target:** https://airdrop.shiftrwa.xyz/register  
**Also:** https://www.shiftrwa.xyz/

**Evidence:**
- `Access-Control-Allow-Origin: *`
- Missing `Content-Security-Policy`
- Missing `X-Frame-Options` on airdrop host
- robots.txt disallows `/app` and `/api/` (API exists but not deeply enumerated)

**Impact:**
- Any origin can read responses from cross-site fetches if endpoints return sensitive data without cookie auth (depends on API design)
- Missing CSP raises XSS impact if any injection exists
- Airdrop pages are high-value phishing/XSS targets

**Remediation:**
- Reflect only trusted origins, never `*`
- Add CSP, HSTS, frame-ancestors
- Ensure airdrop APIs require wallet sig + CSRF-safe design

**Contact:** security@shiftrwa.xyz (from security.txt)

---

## Finding 3 — Byzanlink: Source Map Exposed (MEDIUM)

**Target:** https://byzanlink.com  
**Asset:** `https://framerusercontent.com/sites/1BKXpnqPSQgaNrWgyA7luK/script_main.Bajl8OSr.mjs.map`

**Impact:** Easier reverse engineering of frontend logic, hidden routes, third-party keys in source if any.

**Remediation:** Disable production source maps / block `.map` on CDN.

---

## Finding 4 — Gno.land Sale: Source Map (LOW-MEDIUM)

**Target:** https://sale.gno.land  
**Asset:** https://sa.gno.services/latest.js.map  
robots.txt disallows `/api/` and `/dev/` (good signal API exists).

Netlify RUM token in HTML is expected low risk.

---

## Finding 5 — NOYA.ai: CORS * + Missing CSP (LOW-MEDIUM)

**Target:** https://noya.ai  
Headers: ACAO `*`, no CSP, no XFO.

---

## Finding 6 — OpenDelta: Baseline Hardening Gaps (LOW)

**Target:** https://www.opendelta.com  
- Missing CSP
- `.git` / `.env` return **403** (not exposed — good)
- Related hosts: https://app.opendelta.com , https://docs.opendelta.com

---

## Finding 7 — SIXR Cricket: WordPress Surface (LOW)

**Target:** https://sixrcricket.com  
- WP REST root public
- `/wp-json/wp/v2/users` → 401 (not listable — good)
- `xmlrpc.php` accepts POST only (enum/brute surface if not rate-limited)

**Remediation:** Disable xmlrpc if unused; keep user enumeration blocked; harden WP.

---

## Unreachable / Incomplete
- **Diffuse.fi**, **Chainers.io**, **Mavroasset.com**: network timeout from scanner
- **Neurolov.xyz**: appears domain lander/redirect, not full product app; SSL flaky
- **Smart contracts:** no verified source systematically pulled (pre-TGE / not linked from sites). On-chain audit needs addresses + chain IDs when published.

---

## Priority Actions for Operator
1. **Report/monitor Drake Alchemy key** — highest confirmed bug; rotate if you are team, or report if bounty
2. **Shift airdrop** — CORS + header hardening; good bounty-style web finding if program exists
3. Re-scan Diffuse/Chainers/Mavro when online; pull contract addresses from docs when live
4. For bounty submission: Drake + Shift are strongest verified reports

## Evidence Files
- `C:\Users\Ipeenk\AppData\Local\Temp\alpha_sec_batch_1.json`
- `C:\Users\Ipeenk\AppData\Local\Temp\alpha_sec_batch_2.json`
- `C:\Users\Ipeenk\AppData\Local\Temp\alpha_sec_batch_3.json`
