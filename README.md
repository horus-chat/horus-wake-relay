# Horus wake relay

Content-free APNs / FCM **wake ping**. The VPS stores `wake_id → device token` only. Ciphertext still travels on Tor onion mailboxes. Message bodies are never accepted, stored, or logged.

Apps talk to this host **through Tor SOCKS** (`127.0.0.1:9050`). Outbound to Apple and Google is clearnet (required).

```text
GET    /health
POST   /register     { "wake_id", "platform": "ios"|"android", "token" }
DELETE /register     { "wake_id", "token" }
POST   /wake         { "wake_id" }
```

`wake_id` is a random capability (32+ URL-safe chars). Knowing it is enough to ping. Rate limit: 30 wakes / hour / id.

---

## 1. Oracle Cloud ARM instance

You must create this in the OCI console (this repo cannot log in for you).

Free Tier: **VM.Standard.A1.Flex**, image **Canonical Ubuntu 24.04**, **aarch64**. Start **1 OCPU / 6 GB** (you can raise to 2 / 12 later). Always-free A1 budget is **4 OCPU / 24 GB account-wide**.

1. Open [cloud.oracle.com](https://cloud.oracle.com) → **Compute → Instances → Create instance**.
2. Name it (e.g. `horus-wake`). Placement: any availability domain that still has A1 capacity.
3. Image: **Canonical Ubuntu 24.04**. Shape: **VM.Standard.A1.Flex** → 1 OCPU, 6 GB RAM.
4. Networking: public subnet, **assign a public IPv4**.
5. SSH keys: paste your public key (`~/.ssh/id_ed25519.pub` or generate one with `ssh-keygen -t ed25519`).
6. Create. Copy the public IP.
7. **Virtual cloud network → Security list** (or NSG on the VNIC):
   - Ingress TCP **22** from `0.0.0.0/0` (or lock to your IP).
   - Ingress TCP **443** from `0.0.0.0/0`.
   - Egress **all** (Let’s Encrypt, `api.push.apple.com`, `fcm.googleapis.com`, `oauth2.googleapis.com`).
8. SSH: `ssh -i ~/.ssh/<key> ubuntu@<public-ip>`
9. Point a DNS **A record** you control at that IP (Caddy needs a hostname for TLS).

If A1 is out of capacity, retry another AD or wait — this is the usual Free Tier friction.

---

## 2. APNs Auth Key (.p8)

1. [Apple Developer → Keys](https://developer.apple.com/account/resources/authkeys/list) → **+**.
2. Name it, enable **Apple Push Notifications service (APNs)** → Continue → Register.
3. Download the `.p8` **once**. Record **Key ID** and **Team ID** (Membership).
4. Identifiers → App ID `com.julienlhk.horus` → enable **Push Notifications**.
5. Copy the `.p8` only onto the VPS (`/etc/horus/AuthKey_XXXX.p8`, mode `600`). Never ship it in the iOS app.

Xcode debug uses the **sandbox** APNs environment (`aps-environment` = `development` in entitlements). TestFlight / App Store need `production` and `APNS_SANDBOX=false`. The relay retries the other host on `BadDeviceToken`.

---

## 3. Firebase / FCM (Android)

1. [Firebase console](https://console.firebase.google.com) → Add project → Add Android app `com.julienlhk.horus`.
2. Download `google-services.json` into `apps/mobile/android/app/` (gitignored). Gradle applies the Google Services plugin only when that file exists.
3. Project settings → **Service accounts → Generate new private key**. Put the JSON on the VPS only (`/etc/horus/fcm.json`, mode `600`).
4. Enable **Firebase Cloud Messaging API (V1)** if the console asks.

The wake-relay uses **HTTP v1 REST** with that service account. It does **not** use the Firebase Admin SDK.

---

## 4. Install on the VM

```bash
sudo apt update
sudo apt install -y build-essential pkg-config curl git caddy
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# from a clone of this repo
cargo build --release --manifest-path infrastructure/relays/wake-relay/Cargo.toml
sudo install -m 755 target/release/horus-wake-relay /usr/local/bin/horus-wake-relay

sudo mkdir -p /etc/horus /var/lib/horus
sudo cp /path/to/AuthKey_XXXX.p8 /etc/horus/AuthKey.p8
# optional until Firebase exists:
# sudo cp /path/to/fcm-service-account.json /etc/horus/fcm.json
sudo chmod 600 /etc/horus/*
sudo chown ubuntu:ubuntu /var/lib/horus
```

Env file `/etc/horus/wake.env` (see [`deploy/env.example`](deploy/env.example)):

```
HORUS_WAKE_ADDR=127.0.0.1:8789
HORUS_WAKE_DB=/var/lib/horus/wake_tokens.sqlite
APNS_KEY_PATH=/etc/horus/AuthKey.p8
APNS_KEY_ID=XXXXXXXXXX
APNS_TEAM_ID=XXXXXXXXXX
APNS_TOPIC=com.julienlhk.horus
APNS_SANDBOX=true
FCM_SERVICE_ACCOUNT_JSON=/etc/horus/fcm.json
```

Caddyfile (replace the hostname):

```
wake.example.com {
    reverse_proxy 127.0.0.1:8789
}
```

```bash
sudo cp infrastructure/relays/wake-relay/deploy/horus-wake-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now horus-wake-relay
sudo systemctl reload caddy
curl -sS https://wake.example.com/health
```

Then set `wake_relay` in `environments/prod/config.json` to `https://wake.example.com` and run `./infrastructure/scripts/sync_config.sh prod`. Empty string leaves the feature off.

---

## 5. What this is not

- Not a message store. No queues of ciphertext.
- Not ntfy / OneSignal / UnifiedPush / Firebase Admin.
- Not iMessage-level reliability. iOS can still delay or drop wakes; force-quit + Focus + Low Power remain limits. The banner is always generic.
