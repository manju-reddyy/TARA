"""Public verifier for TARA's signed records. Needs only public keys, never a secret.

  python verify.py audit   [--audit PATH] [--secrets DIR] [--pub HEX ...]
  python verify.py receipt R-XXXXXXXX [--receipts PATH] [--secrets DIR] [--pub HEX ...]
  python verify.py pubkey  [--secrets DIR]

Public keys are read from <secrets>/signing_pubs.json (the rotation history) unless --pub is
given. Exit code 0 if everything verifies, 1 otherwise. This script reads only public material;
point it at a copy of the audit log and the published public key to check records independently.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core  # noqa: E402

RECEIPT_FIELDS = ("request_id", "job", "action", "action_hash", "level", "via", "at")


def _pubs(secrets_dir, explicit):
    if explicit:
        return list(explicit)
    try:
        with open(os.path.join(secrets_dir, "signing_pubs.json"), encoding="utf-8") as f:
            return list(json.load(f).get("pubs") or [])
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(secrets_dir, "signing_pub.hex"), encoding="utf-8") as f:
            return [f.read().strip()]
    except OSError:
        return []


def _entries(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


def _verify_rotation_chain(path):
    """Every key_rotation entry must carry a transition signature valid under the old public key
    over the new one, so the chain of signing keys is itself verifiable."""
    try:
        rotations = [e for e in _entries(path) if e.get("event") == "key_rotation"]
    except OSError as e:
        return False, str(e)
    for e in rotations:
        if not core.verify_sig(e.get("old_pubkey", ""), e.get("new_pubkey", ""),
                               e.get("transition_sig", "")):
            return False, f"bad transition signature at seq {e.get('seq')}"
    return True, f"{len(rotations)} rotation(s) verified"


def cmd_audit(args):
    pubs = _pubs(args.secrets, args.pub)
    ok, n, msg = core.verify_audit(args.audit, pubs or None, require_signed=bool(pubs))
    print(f"audit: {'VALID' if ok else 'INVALID'} - {msg} ({n} entries checked)")
    chain_ok = True
    if pubs:
        chain_ok, chain_msg = _verify_rotation_chain(args.audit)
        print(f"rotation chain: {'VALID' if chain_ok else 'INVALID'} - {chain_msg}")
    else:
        print("no public key found; checked the hash chain only (pass --pub or --secrets)")
    return 0 if (ok and chain_ok) else 1


def cmd_receipt(args):
    pubs = _pubs(args.secrets, args.pub)
    try:
        recs = _entries(args.receipts)
    except OSError as e:
        print(f"receipt: INVALID - {e}")
        return 1
    rec = next((r for r in recs if r.get("receipt") == args.id), None)
    if not rec:
        print(f"receipt: NOT FOUND - {args.id}")
        return 1
    body = {k: rec.get(k) for k in RECEIPT_FIELDS}
    ok = core.verify_sig(rec.get("pubkey", ""), core.canonical(body), rec.get("ed25519", ""))
    trusted = (not pubs) or (rec.get("pubkey") in pubs)
    print(f"receipt {args.id}: {'VALID' if ok and trusted else 'INVALID'}")
    if ok:
        print(f"  action: {rec.get('action')}")
        print(f"  level : {rec.get('level')}   via: {rec.get('via')}")
        if not trusted:
            print("  WARNING: signed by a key outside the trusted public-key set")
    return 0 if (ok and trusted) else 1


def cmd_pubkey(args):
    pubs = _pubs(args.secrets, None)
    if not pubs:
        print("no public key found")
        return 1
    print("current:", pubs[-1])
    for p in pubs[:-1]:
        print("retired:", p)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify TARA signed records with public keys only.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    receipts_default = os.path.join(os.path.dirname(core.AUDIT_PATH), "receipts.jsonl")

    a = sub.add_parser("audit", help="verify the audit log's chain and signatures")
    a.add_argument("--audit", default=core.AUDIT_PATH)
    a.add_argument("--secrets", default=core.SECRETS_DIR)
    a.add_argument("--pub", nargs="*")
    a.set_defaults(func=cmd_audit)

    r = sub.add_parser("receipt", help="verify one approval receipt by id")
    r.add_argument("id")
    r.add_argument("--receipts", default=receipts_default)
    r.add_argument("--secrets", default=core.SECRETS_DIR)
    r.add_argument("--pub", nargs="*")
    r.set_defaults(func=cmd_receipt)

    p = sub.add_parser("pubkey", help="print the current and retired public keys")
    p.add_argument("--secrets", default=core.SECRETS_DIR)
    p.set_defaults(func=cmd_pubkey)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
