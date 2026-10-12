# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 Roberto Locatelli
"""Optional: rerun the 25 vectors with Ed25519 verification done by the `cryptography` package instead of
ed25519_rfc8032.verify; the per-vector reports must be identical."""
import json, sys
import acceptance_check as ac, ed25519_rfc8032 as ed, misura_vettori as mv
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("cryptography not installed: skipped"); sys.exit(0)
doc = json.load(open("fonti/5a4ea06_vectors.json"))
mine = [ac.check(v["case"]) for v in doc["vectors"]]
def ref_verify(pub, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg); return True
    except (InvalidSignature, ValueError):
        return False
ed.verify = ref_verify
theirs = [ac.check(v["case"]) for v in doc["vectors"]]
diff = [v["id"] for v, a, b in zip(doc["vectors"], mine, theirs) if a != b]
print("reports differing between stdlib Ed25519 and cryptography:", len(diff), diff)
sys.exit(1 if diff else 0)
