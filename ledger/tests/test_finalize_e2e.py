"""End-to-end check of finalizeElection against a running Gateway (plays Core and the Rule Engine).

  python3 -I ledger/tests/test_finalize_e2e.py --env .env.gw [--gateway http://127.0.0.1:8100]

Needs the same setup as test_gateway_e2e.py and the contract of this change deployed. It runs one election through
open, early close (ALL_VOTED), CLOSE_FINAL, TALLY_PUBLISHED, then checks that ELECTION_FINALIZED is refused until the
TALLY checkpoint exists, a finding of each of R1 to R5 is recorded at it, and every INCONCLUSIVE finding is superseded
by a later PASS; a wrong result_hash is refused; the correct request is accepted, anchored, and the state is FINALIZED.
About 70 s.
"""
import argparse
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "gateway"))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import pv_hash  # noqa: E402
import test_findings_e2e as f  # noqa: E402  (finding_body, post_until)
import test_gateway_e2e as t  # noqa: E402  (Gw, event, until_final, check, rid, iso)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", default=".env")
    ap.add_argument("--gateway", default="http://127.0.0.1:8100")
    a = ap.parse_args()
    env = {}
    for ln in open(a.env, encoding="utf-8").read().splitlines():
        m = re.match(r"^([A-Z0-9_]+)=(\S*)", ln)
        if m:
            env[m.group(1)] = m.group(2)
    gw = t.Gw(a.gateway, env["CORE_KEY"])
    rule_key = env["RULE_KEY"]
    priv = int(env["RULE_ENGINE_SIGNER_KEY"], 16)
    check = t.check

    st, orgs = gw.get("/v1/organizations")
    names = sorted(o["org_id"] for o in orgs["items"])
    el, bucket, now = t.rid("elc_"), 5, int(time.time())
    ws = (now + 20) // bucket * bucket + bucket
    we = ws + 60
    closed_at = ws + 10
    print(f"election {el}, window {t.iso(ws)} .. {t.iso(we)}, early close at {t.iso(closed_at)}")
    created = {"config_hash": pv_hash.H("config-" + el), "window_start": t.iso(ws), "window_end": t.iso(we),
               "time_bucket_seconds": bucket, "checkpoint_interval_seconds": 10, "candidate_count": 2,
               "organizations": [{"org_id": o, "signer": "0x" + "00" * 20} for o in names], "approval_threshold": 2,
               "public_key_hash": pv_hash.H("pk"), "proposal_ttl_hours": 24, "operator_org": "org_commission"}
    roster = pv_hash.set_root([pv_hash.H("voter-%d" % i) for i in range(3)])
    troot = pv_hash.set_root([pv_hash.H("token-%d" % i) for i in range(3)])
    tables = [{"table": "t%d" % i, "row_count": 0, "snapshot_hash": pv_hash.H("t%d" % i)} for i in range(6)]

    def cp(n, reason):
        return {"checkpoint": n, "reason": reason, "tables": tables, "counts": {}, "voter_events": {}}

    result_hash = pv_hash.H("result-" + el)
    tally = {"final_checkpoint": 1, "ballot_count": 0, "invalid_ballots": 0, "excluded_ballots": 0,
             "invalid_ballot_hashes": [], "results": [], "ballot_set_root": pv_hash.H("bsr"), "result_hash": result_hash}
    steps = [("ELECTION_CREATED", 0, created, now),
             ("ROSTER_FROZEN", 0, {"roster_hash": roster, "voter_count": 3}, now),
             ("TOKEN_BATCH_ISSUED", 0, {"batch_no": 1, "token_count": 3, "token_set_root": troot}, now),
             ("CHECKPOINT_COMMITTED", 0, cp(0, "STATE_CHANGE"), now),
             ("ELECTION_OPENED", 1, {"window_start": t.iso(ws), "window_end": t.iso(we)}, ws),
             ("ELECTION_CLOSED", 1, {"reason": "ALL_VOTED", "closed_at": t.iso(closed_at)}, closed_at),
             ("CHECKPOINT_COMMITTED", 1, cp(1, "CLOSE_FINAL"), closed_at),
             ("TALLY_PUBLISHED", 1, tally, closed_at)]
    for seq, (typ, ckpt, payload, occurred) in enumerate(steps, 1):
        r = t.until_final(gw, t.event(el, typ, seq, ckpt, payload, occurred), budget=90)
        check(f"setup: {typ} accepted", r["status"] in ("ACCEPTED", "DUPLICATE"), r)
    seqn = [len(steps) + 1]    # a REJECTED event keeps its seq too: every attempt takes the next one

    def take():
        seqn[0] += 1
        return seqn[0] - 1

    st, s = gw.get(f"/v1/elections/{el}/state")
    check("state is TALLIED with the tally's result_hash", s.get("status") == "TALLIED" and s.get("result_hash") == result_hash, s)

    def finalize(rh, why):
        r = t.until_final(gw, t.event(el, "ELECTION_FINALIZED", take(), 2, {"result_hash": rh}, int(time.time())))
        return r

    # ---- refused until the TALLY checkpoint exists
    r = finalize(result_hash, "no TALLY checkpoint")
    check("finalize before the TALLY checkpoint is REJECTED INVALID_STATE_TRANSITION",
          r["status"] == "REJECTED" and r.get("reject_code") == "INVALID_STATE_TRANSITION"
          and "TallyCheckpointMissing" in r.get("detail", ""), r)
    r = t.until_final(gw, t.event(el, "CHECKPOINT_COMMITTED", take(), 2, cp(2, "TALLY"), int(time.time())))
    check("the TALLY checkpoint is accepted while TALLIED", r["status"] in ("ACCEPTED", "DUPLICATE"), r)

    # ---- no findings yet
    r = finalize(result_hash, "no findings")
    check("finalize without findings is REJECTED FINDING_NOT_RECORDED",
          r["status"] == "REJECTED" and r.get("reject_code") == "FINDING_NOT_RECORDED", r)

    # ---- R1 to R4 PASS, R5 INCONCLUSIVE at the TALLY checkpoint
    def record(rule, result, label):
        body = f.finding_body(priv, el, t.rid("fnd_"), rule, result, 2, pv_hash.H(label))
        st, out = f.post_until(gw, body, rule_key)
        check(f"finding {rule} {result} recorded (200 or 201)", st in (200, 201) and "event_id" in out, (st, out))
        return body["finding_id"]

    for rule in ("R1", "R2", "R3", "R4"):
        record(rule, "PASS", f"{rule}-pass")
    inc = record("R5", "INCONCLUSIVE", "R5-inconclusive")
    r = finalize(result_hash, "pending INCONCLUSIVE")
    check("finalize with an unresolved INCONCLUSIVE finding is REJECTED FINDINGS_UNREVIEWED",
          r["status"] == "REJECTED" and r.get("reject_code") == "FINDINGS_UNREVIEWED", r)
    st, fl = gw.get(f"/v1/finding-records?election_id={el}")
    by_id = {x["finding_id"]: x for x in fl.get("items", [])}
    check("the INCONCLUSIVE finding is PENDING", by_id.get(inc, {}).get("contract_status") == "PENDING", fl)

    # ---- a later PASS of R5 at the same checkpoint supersedes it
    ok5 = record("R5", "PASS", "R5-pass")
    st, fl = gw.get(f"/v1/finding-records?election_id={el}")
    by_id = {x["finding_id"]: x for x in fl.get("items", [])}
    check("the INCONCLUSIVE finding is SUPERSEDED by the later PASS",
          by_id.get(inc, {}).get("contract_status") == "SUPERSEDED"
          and by_id.get(ok5, {}).get("contract_status") == "NOT_REQUIRED", fl)

    # ---- result_hash must equal the tally
    r = finalize(pv_hash.H("another result"), "wrong hash")
    check("finalize with another result_hash is REJECTED (ResultHashMismatch)",
          r["status"] == "REJECTED" and "ResultHashMismatch" in r.get("detail", ""), r)

    # ---- the real one
    ev = t.event(el, "ELECTION_FINALIZED", take(), 2, {"result_hash": result_hash}, int(time.time()))
    r = t.until_final(gw, ev)
    check("finalize with every condition met is ACCEPTED", r["status"] in ("ACCEPTED", "DUPLICATE")
          and r.get("tx_hash"), r)
    st, s = gw.get(f"/v1/elections/{el}/state")
    check("state read from chain: FINALIZED", s.get("status") == "FINALIZED", s)
    end = time.time() + 40
    while time.time() < end:
        st, e1 = gw.get("/v1/events/" + ev["event_id"])
        if st == 200 and e1["anchor"]["status"] == "ANCHORED":
            break
        time.sleep(1)
    check("ELECTION_FINALIZED is anchored (immediate)", st == 200 and e1["anchor"]["status"] == "ANCHORED"
          and e1["anchor"]["mode"] == "immediate", e1)
    r = t.until_final(gw, t.event(el, "ELECTION_FINALIZED", take(), 2, {"result_hash": result_hash}, int(time.time())))
    check("a second finalize is REJECTED INVALID_STATE_TRANSITION", r["status"] == "REJECTED"
          and r.get("reject_code") == "INVALID_STATE_TRANSITION", r)

    end = time.time() + 40
    while True:
        st, h = gw.get("/v1/health")
        if h.get("pending_events") == 0 or time.time() > end:
            break
        time.sleep(1)
    check("health ok and nothing pending", h["status"] == "ok" and h["pending_events"] == 0, h)
    print(("\n%d check(s) failed" % len(t.FAILED)) if t.FAILED else "\nall checks passed")
    sys.exit(1 if t.FAILED else 0)


if __name__ == "__main__":
    main()
