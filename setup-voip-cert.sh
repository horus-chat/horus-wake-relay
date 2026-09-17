#!/bin/bash
# ============================================================
# VoIP Services Certificate → Server Private Key Setup
# ============================================================
# Run this on your Mac ONCE to export the private key that
# matches the voip_cert.pem already in this directory.
#
# Prerequisites:
#   - The VoIP Services certificate must be imported into Keychain
#     (double-click voip_services.cer or it was imported automatically
#     when you downloaded it from Apple Developer)
#   - Your Keychain must be unlocked
#
# Output:
#   voip_key.pem  — private key PEM (keep secret, .gitignore'd)
#
# After running:
#   Configure the wake-relay server with:
#     APNS_VOIP_CERT_PEM=/path/to/wake-relay/voip_cert.pem
#     APNS_VOIP_KEY_PEM=/path/to/wake-relay/voip_key.pem
#
# NOTE: The current wake-relay uses JWT-based APNs auth (.p8 key).
#       If you have a .p8 API key, set:
#         APNS_KEY_PATH=/path/to/AuthKey_XXXXXXXX.p8
#         APNS_KEY_ID=XXXXXXXX
#         APNS_TEAM_ID=XXXXXXXXXX
#       The .p8 key works for ALL push types including VoIP
#       (just set APNS_VOIP_TOPIC=com.julienlhk.horus.voip).
# ============================================================

set -e

CERT_PEM="$(dirname "$0")/voip_cert.pem"
KEY_OUT="$(dirname "$0")/voip_key.pem"
P12_TMP="/tmp/voip_services_export.p12"

if [ ! -f "$CERT_PEM" ]; then
    echo "ERROR: voip_cert.pem not found in $(dirname "$0")"
    exit 1
fi

echo "Looking for VoIP Services private key in Keychain..."
echo "You will be prompted for your Keychain password."
echo ""

# Export the identity (cert + private key) as a P12 bundle.
# The cert label in Keychain matches the Subject CN.
security export \
    -k ~/Library/Keychains/login.keychain-db \
    -t identities \
    -f pkcs12 \
    -P "" \
    -o "$P12_TMP" 2>/dev/null || {
    echo "Automatic export failed. Trying interactive export..."
    # Try without -P (prompts for export password)
    security export \
        -k ~/Library/Keychains/login.keychain-db \
        -t identities \
        -f pkcs12 \
        -o "$P12_TMP"
}

if [ ! -f "$P12_TMP" ]; then
    echo ""
    echo "MANUAL FALLBACK:"
    echo "1. Open Keychain Access"
    echo "2. Find 'VoIP Services: com.julienlhk.horus'"
    echo "3. Right-click → Export Items..."
    echo "4. Save as: $P12_TMP"
    echo "5. Re-run this script"
    exit 1
fi

echo ""
echo "Extracting private key from P12..."
echo "(If prompted for import password, press Enter for empty password)"

openssl pkcs12 \
    -in "$P12_TMP" \
    -nocerts \
    -nodes \
    -out "$KEY_OUT" \
    -passin pass: 2>/dev/null || \
openssl pkcs12 \
    -in "$P12_TMP" \
    -nocerts \
    -nodes \
    -out "$KEY_OUT" \
    -legacy

rm -f "$P12_TMP"

if [ -f "$KEY_OUT" ]; then
    chmod 600 "$KEY_OUT"
    echo ""
    echo "✅ voip_key.pem written successfully."
    echo ""
    echo "Next steps for the server:"
    echo "  If using JWT auth (.p8), this file is not needed."
    echo "  If using cert auth:"
    echo "    APNS_VOIP_CERT_PEM=$(realpath "$CERT_PEM")"
    echo "    APNS_VOIP_KEY_PEM=$(realpath "$KEY_OUT")"
else
    echo "ERROR: Could not extract private key."
    exit 1
fi
