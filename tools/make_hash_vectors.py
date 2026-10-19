"""Generate (or check) tests/vectors/hash-vectors.json — shared test vectors for every hashing.md value that
modules compare with each other (leaf_hash, rejection_leaf, rejections_root, target_hash, config_hash, roster_hash,
token_set_root, receipt_hash, ballot_set_root, result_hash, snapshot_hash, signature digests).

Every module (Core, Gateway, contract, Rule Engine) loads the file in its own tests and must reproduce each `expected`
from its `input`. The values are computed with the reference functions below (same as tools/validate_contracts.py).

Usage:  python tools/make_hash_vectors.py           # write the file
        python tools/make_hash_vectors.py --check   # CI: fail if the file differs from a fresh computation
"""
import hashlib
import json
import sys
from pathlib import Path

import base64

import rfc8785
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry
from referencing.jsonschema import DRAFT202012

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "tests" / "vectors" / "hash-vectors.json"
EX = REPO / "contracts" / "examples" / "valid" / "ledger-events"
CONTRACTS = REPO / "contracts"


def row_validator(name):
    """Validator for a view row schema of core-api.openapi.yaml (refs into common.schema.json resolved)."""
    common = json.loads((CONTRACTS / "common.schema.json").read_text(encoding="utf-8"))
    api = yaml.safe_load((CONTRACTS / "core-api.openapi.yaml").read_text(encoding="utf-8"))
    schema = dict(api["components"]["schemas"][name])
    schema["$id"] = "https://purevoting2.local/contracts/core-api.openapi.yaml"
    reg = Registry().with_resource("https://purevoting2.local/contracts/common.schema.json", DRAFT202012.create_resource(common))
    return Draft202012Validator(schema, registry=reg)


def checked_rows(schema_name, rows):
    v = row_validator(schema_name)
    for r in rows:
        errs = list(v.iter_errors(r))
        if errs:
            raise SystemExit(f"FAIL vector row does not match {schema_name}: {errs[0].message}")
    return rows


def H(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return rfc8785.dumps(obj).decode("utf-8")


def Hc(obj):
    return H(rfc8785.dumps(obj))


def merkle_root(leaves):
    level = list(leaves)
    if not level:
        return H("")
    while len(level) > 1:
        nxt = [H(level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def set_root(values):
    return merkle_root(sorted(set(values)))


def tag(s):
    b = s.encode("ascii")
    return b + b"\x00" * (32 - len(b))


def idh(x):
    return hashlib.sha256(x.encode("utf-8")).digest()


def u(n):
    return n.to_bytes(32, "big")


ACTION = {"ROSTER_AMEND": 1, "TOKEN_REISSUE": 2, "WINDOW_CHANGE": 3, "ELECTION_CLOSE_EARLY": 4, "ELECTION_VOID": 5}


def proposal_digest(p, a, e, t, th, org, dec):
    return hashlib.sha256(tag("PV2-PROPOSAL-v1") + idh(p) + idh(a) + idh(e) + u(ACTION[t]) + bytes.fromhex(th)
                          + idh(org) + u(dec)).hexdigest()


def finding_digest(f, e, rule, result, cp, fh):
    return hashlib.sha256(tag("PV2-FINDING-v1") + idh(f) + idh(e) + u(rule) + u(result) + u(cp)
                          + bytes.fromhex(fh)).hexdigest()


def review_digest(f, e, fh, org, dec, nh):
    return hashlib.sha256(tag("PV2-REVIEW-v1") + idh(f) + idh(e) + bytes.fromhex(fh) + idh(org) + u(dec)
                          + bytes.fromhex(nh)).hexdigest()


def leaf_input(name):
    ev = json.loads((EX / name).read_text(encoding="utf-8"))
    ev.pop("received_at", None)
    ev.pop("anchor", None)
    return ev


def build():
    Z = "0" * 26
    E = "elc_WXWCBYB6WK952SWA0432CF1XMW"
    v = []

    def add(name, formula, inp, expected):
        v.append({"name": name, "formula": formula, "input": inp, "expected": expected})

    # primitives
    add("H_empty", "H('')", "", H(""))
    add("H_text", "H(utf8)", "PureVoting", H("PureVoting"))
    obj = {"b": 1, "a": "x", "c": {"z": [3, 1], "y": None}}
    add("canonical", "RFC 8785 JCS text", obj, canonical(obj))
    add("Hc", "H(canonical(obj))", obj, Hc(obj))
    leaves = [H(str(i)) for i in range(1, 6)]
    for n in (0, 1, 2, 3, 5):
        add(f"merkle_root_{n}", "merkle_root(leaves in order; odd node carried up; empty = H(''))", leaves[:n],
            merkle_root(leaves[:n]))
    dup = [leaves[2], leaves[0], leaves[1], leaves[0]]
    add("set_root_dedup", "merkle_root(sorted, duplicates removed)", dup, set_root(dup))

    # ledger events
    for f in ("token_used.json", "election_created.json"):
        ev = leaf_input(f)
        add(f"leaf_hash_{f[:-5]}", "Hc(event without received_at and anchor)", ev, Hc(ev))
        add(f"payload_hash_{f[:-5]}", "Hc(payload)", ev["payload"], Hc(ev["payload"]))
    rej = [{"rejection_id": "rej_" + "1" * 26, "election_id": E, "event_id": "evr_" + "2" * 26, "type": "BALLOT_RECEIVED",
            "checkpoint": 9, "reject_code": "ELECTION_NOT_OPEN", "recorded_at": "2026-11-03T11:00:05Z",
            "payload_hash": H("p1"), "subject_hash": None},
           {"rejection_id": "rej_" + "3" * 26, "election_id": E, "event_id": "evr_" + "4" * 26, "type": "TOKEN_USED",
            "checkpoint": 9, "reject_code": "DUPLICATE_CONTENT", "recorded_at": "2026-11-03T11:00:06Z",
            "payload_hash": H("p2"), "subject_hash": H("token")}]
    for i, r in enumerate(rej):
        add(f"rejection_leaf_{i}", "Hc(9 rejection fields; subject_hash null if absent)", r, Hc(r))
    add("rejections_root", "set_root(rejection_leaf ...)", rej, set_root([Hc(r) for r in rej]))
    add("rejections_root_none", "H('') if no rejection", [], H(""))

    # voter values
    token, cred = "q2Vb3kX9mJ7pL0sT4wYz1A", "Zt8Kp2Lm9Qx4Rv7Ws1Bc3D"
    add("token_hash", "H(token)", token, H(token))
    add("nullifier_hash", "H(credential)", cred, H(cred))
    sealed = bytes(range(48))
    add("ballot_hash", "H(raw sealed_ballot bytes) — input is the bytes as hex", sealed.hex(), H(sealed))
    rc = {"election_id": E, "nullifier_hash": H(cred), "ballot_hash": H(sealed)}
    add("receipt_hash", "Hc({election_id, nullifier_hash, ballot_hash})", rc, Hc(rc))

    # roster / tokens
    vks = ["vtr_" + c * 26 for c in "CBA"]
    add("roster_hash", "set_root([H(voter_key) for ACTIVE voters])", vks, set_root([H(k) for k in vks]))
    ths = [H("t1"), H("t2"), H("t3")]
    add("token_set_root", "set_root([token_hash of tokens not revoked])", ths, set_root(ths))

    # config_hash
    cfg = {"title": "Student council 2026",
           "candidates": [{"candidate_id": "cand_" + "A" * 26, "name": "Kim"}, {"candidate_id": "cand_" + "B" * 26, "name": "Lee"}],
           "window_start": "2026-11-03T09:00:00Z", "window_end": "2026-11-03T11:00:00Z",
           "time_bucket_seconds": 900, "checkpoint_interval_seconds": 900,
           "organizations": [{"org_id": "org_commission", "signer": "0x" + "a1" * 20},
                             {"org_id": "org_neutral", "signer": "0x" + "c3" * 20},
                             {"org_id": "org_observer", "signer": "0x" + "b2" * 20}],
           "approval_threshold": 2, "proposal_ttl_hours": 24, "operator_org": "org_commission",
           "public_key_hash": H(bytes(32))}
    add("config_hash", "Hc(config object; candidates and organizations sorted; window values at creation)", cfg, Hc(cfg))

    # target_hash per action type
    A = "act_" + Z
    targets = {"ROSTER_AMEND": {"add": ["vtr_" + "D" * 26], "remove": []},
               "TOKEN_REISSUE": {"voter_keys": ["vtr_" + "A" * 26]},
               "WINDOW_CHANGE": {"new_window_end": "2026-11-03T11:30:00Z"},
               "ELECTION_CLOSE_EARLY": {"closed_at": "2026-11-03T10:30:00Z"},
               "ELECTION_VOID": {"finding_ids": []}}
    for t, tgt in targets.items():
        o = {"election_id": E, "action_id": A, "action_type": t, "target": tgt}
        add(f"target_hash_{t}", "Hc({election_id, action_id, action_type, target})", o, Hc(o))

    # tally
    bh = [H("b2"), H("b1"), H("b2")]
    add("ballot_set_root_duplicates", "merkle_root(sorted ballot_hash, duplicates KEPT) — formula only", bh, merkle_root(sorted(bh)))
    tb = [H("b1"), H("b2"), H("b3")]
    res = {"election_id": E, "final_checkpoint": 9,
           "results": [{"candidate_id": "cand_" + "A" * 26, "votes": 1}, {"candidate_id": "cand_" + "B" * 26, "votes": 1},
                       {"candidate_id": "cand_" + "C" * 26, "votes": 0}],
           "ballot_count": 2, "invalid_ballots": 1, "invalid_ballot_hashes": [H("b3")], "excluded_ballots": 0,
           "ballot_set_root": merkle_root(sorted(tb))}
    add("result_hash", "Hc(result object; every candidate incl. 0 votes, sorted) — consistent tally: 3 accepted ballots, b3 invalid", res, Hc(res))

    # snapshot_hash: rows exactly as returned by GET /internal/v1/views/{view}, validated against the core-api Row* schemas
    rows = checked_rows("RowRoster", [
        {"view": "roster", "row_key": "vtr_" + "A" * 26, "status": "ACTIVE", "added_checkpoint": 0, "removed_checkpoint": None},
        {"view": "roster", "row_key": "vtr_" + "B" * 26, "status": "REMOVED", "added_checkpoint": 0, "removed_checkpoint": 3}])
    add("snapshot_hash_roster", "Hc(all rows as of k, sorted by row_key; rows exactly as returned by GET /internal/v1/views/roster, schema-validated)",
        rows, Hc(rows))
    sealed2 = bytes(range(100, 147))          # 47 bytes -> standard base64 ends with '='
    n1, n2 = H("cred-1"), H("cred-2")
    def receipt_row(nh, raw, ev):
        return {"view": "ballot_receipts", "row_key": nh, "ballot_hash": H(raw),
                "sealed_ballot": base64.b64encode(raw).decode("ascii"),
                "receipt_hash": Hc({"election_id": E, "nullifier_hash": nh, "ballot_hash": H(raw)}),
                "received_checkpoint": 2, "received_bucket": "2026-11-03T09:15:00Z", "event_id": ev}
    brows = sorted([receipt_row(n1, sealed, "evr_" + "7" * 26), receipt_row(n2, sealed2, "evr_" + "8" * 26)],
                   key=lambda r: r["row_key"])
    checked_rows("RowBallotReceipt", brows)
    add("snapshot_hash_ballot_receipts", "Hc(all rows as of k, sorted by row_key; sealed_ballot = RFC 4648 standard base64 with padding; schema-validated)",
        brows, Hc(brows))

    # signature digests (same inputs as validate_contracts.py)
    add("idh", "sha256(utf8(id)) as hex — also the bytes32 ID on chain", "org_observer", idh("org_observer").hex())
    sig_in = ["prp_" + Z, "act_" + Z, "elc_" + Z, "TOKEN_REISSUE", H("t"), "org_observer"]
    add("request_digest", "PV2-PROPOSAL-v1 layout, decision 0", sig_in + [0], proposal_digest(*sig_in, 0))
    add("approval_digest", "PV2-PROPOSAL-v1 layout, decision 1 (= SIG_DIGEST_VECTOR)", sig_in + [1], proposal_digest(*sig_in, 1))
    f_in = ["fnd_" + Z, "elc_" + Z, 3, 1, 4, H("f")]
    add("finding_record_digest", "PV2-FINDING-v1 layout (= FINDING_DIGEST_VECTOR)", f_in, finding_digest(*f_in))
    r_in = ["fnd_" + Z, "elc_" + Z, H("f"), "org_neutral", 1, H("n")]
    add("review_digest", "PV2-REVIEW-v1 layout (= REVIEW_DIGEST_VECTOR)", r_in, review_digest(*r_in))
    return {"description": "Shared hash test vectors generated from contracts/hashing.md by tools/make_hash_vectors.py. "
                           "Do not edit by hand.", "vectors": v}


def main():
    data = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != data:
            print("FAIL tests/vectors/hash-vectors.json is missing or out of date; run python tools/make_hash_vectors.py")
            sys.exit(1)
        print("ok   tests/vectors/hash-vectors.json is up to date")
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(data, encoding="utf-8", newline="\n")
    print("wrote", OUT.relative_to(REPO))


if __name__ == "__main__":
    main()
