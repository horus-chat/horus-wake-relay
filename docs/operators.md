# Operating horus-wake-relay

Companion to the crate [README](../README.md).

## Threat model (operator view)

You operate a **metadata-minimized** wake host:

| You hold | You must not hold |
|----------|-------------------|
| `wake_id` → device token | Message plaintext |
| Platform (ios/android) | Chat ids, onions, identity keys |
| Push credentials (APNs/FCM) on the VPS | End-user passwords (none exist) |

Peers who know `wake_id` can request a ping (HMAC + rate limit). Document this honestly for users.

## Recommended topology

```text
Internet :443 (Caddy / TLS)
    → 127.0.0.1:8789 (this binary)
Apps → Tor SOCKS → your onion or hostname
Binary → clearnet → api.push.apple.com / FCM
```

- Prefer binding the binary to localhost; terminate TLS at Caddy.  
- Do not log bodies. Prefer minimal access logs.  
- SQLite DB mode `600`, owned by the service user.

## APNs

1. Create an APNs Auth Key in Apple Developer; download `.p8` once.  
2. Note Key ID + Team ID.  
3. Copy `.p8` to the VPS only (`/etc/horus/AuthKey.p8`, mode `600`).  
4. Set `APNS_TOPIC` to the app bundle id.  
5. Xcode debug tokens need `APNS_SANDBOX=true`; TestFlight/App Store usually `false`.

VoIP / PushKit uses the same `.p8` with a `.voip` topic when configured — see comments in `deploy/env.example` and `setup-voip-cert.sh` (legacy cert path; JWT `.p8` is preferred).

## FCM (Android)

1. Firebase project → service account JSON on the VPS only.  
2. Set `FCM_SERVICE_ACCOUNT_JSON` + `FCM_PROJECT_ID`.  
3. Leave unset to return 501 for Android wakes until ready.

## HMAC auth

Clients sign:

```text
v1\n<METHOD>\n<PATH>\n<unix_ts>\n<sha256_hex(body)>
```

Header form: `v1;id=<wake_id>;ts=<unix>;sig=<hmac_hex>`.

Reject if `wake_id` mismatches, timestamp skew > ~300s, or MAC fails. Implementation: `src/auth.rs`.

## Health checks

```bash
curl -sS http://127.0.0.1:8789/health
```

After deploy, confirm APNs/FCM backends printed as enabled in stderr on start.

## Incident notes

- Rotate APNs key if the `.p8` leaks.  
- Wipe SQLite rows for a `wake_id` if a user uninstalls / reports abuse.  
- Rate-limit already caps ping floods; tighten in `src/rate.rs` if needed.

Back to [README](../README.md).
