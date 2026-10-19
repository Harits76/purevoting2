"""Validate everything in contracts/.

- every *.schema.json is a valid JSON Schema (2020-12)
- every OpenAPI file is valid OpenAPI 3.1 and its $refs resolve
- examples/valid/<target>/*.json validate; examples/invalid/<target>/*.json are rejected
  <target> = "<schema>" (e.g. finding) or "<schema>.<$defs name>" (e.g. audit-report.AuditReportSubmission)
- semantic checks the schemas cannot express (ledger examples):
  payload_hash == Hc(payload) (RFC 8785), bucketed times aligned to time_bucket_seconds,
  CHECKPOINT_COMMITTED.payload.checkpoint == event checkpoint, receipt_hash formula
- reference implementation of the hashing.md primitives (H, Hc, merkle_root, set_root) with self-tests

Usage:  pip install -r tools/requirements.txt
        python tools/validate_contracts.py
"""
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

import rfc8785
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from openapi_spec_validator import validate as validate_openapi
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent / "contracts"
errors = []


def fail(msg):
    errors.append(msg)
    print("  FAIL", msg)


# ---- hashing.md reference implementation ----
def H(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


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


def self_test():
    a, b, c = H("a"), H("b"), H("c")
    assert merkle_root([a]) == a
    assert merkle_root([a, b]) == H(a + b)
    assert merkle_root([a, b, c]) == H(H(a + b) + c)  # odd node carried up
    assert set_root([c, a, b, a]) == merkle_root(sorted([a, b, c]))
    assert Hc({"b": 1, "a": "x"}) == H('{"a":"x","b":1}')


# ---- hashing.md "Signatures": fixed binary digest layout (rebuildable on chain) ----
ACTION_CODE = {"ROSTER_AMEND": 1, "TOKEN_REISSUE": 2, "WINDOW_CHANGE": 3, "ELECTION_CLOSE_EARLY": 4, "ELECTION_VOID": 5}
PROPOSAL_DECISION = {"REQUEST": 0, "APPROVE": 1, "REJECT": 2}
REVIEW_DECISION = {"DISMISSED": 1, "ACCEPTED_RISK": 2, "CONFIRMED_ISSUE": 3}
RESULT_CODE = {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}


def tag(s):
    b = s.encode("ascii")
    assert len(b) <= 32
    return b + b"\x00" * (32 - len(b))


def idh(x):
    return hashlib.sha256(x.encode("utf-8")).digest()


def h32(hexstr):
    return bytes.fromhex(hexstr)


def u(n):
    return n.to_bytes(32, "big")


def proposal_digest(proposal_id, action_id, election_id, action_type, target_hash, org_id, decision):
    return hashlib.sha256(tag("PV2-PROPOSAL-v1") + idh(proposal_id) + idh(action_id) + idh(election_id)
                          + u(ACTION_CODE[action_type]) + h32(target_hash) + idh(org_id)
                          + u(PROPOSAL_DECISION[decision])).hexdigest()


def finding_digest(finding_id, election_id, rule_id, result, checkpoint, finding_hash):
    return hashlib.sha256(tag("PV2-FINDING-v1") + idh(finding_id) + idh(election_id) + u(int(rule_id[1]))
                          + u(RESULT_CODE[result]) + u(checkpoint) + h32(finding_hash)).hexdigest()


def review_digest(finding_id, election_id, finding_hash, org_id, decision, note_hash):
    return hashlib.sha256(tag("PV2-REVIEW-v1") + idh(finding_id) + idh(election_id) + h32(finding_hash)
                          + idh(org_id) + u(REVIEW_DECISION[decision]) + h32(note_hash)).hexdigest()


Z = "0" * 26
SIG_DIGEST_VECTOR_INPUT = ("prp_" + Z, "act_" + Z, "elc_" + Z, "TOKEN_REISSUE", H("t"), "org_observer", "APPROVE")
FINDING_DIGEST_VECTOR_INPUT = ("fnd_" + Z, "elc_" + Z, "R3", "FAIL", 4, H("f"))
REVIEW_DIGEST_VECTOR_INPUT = ("fnd_" + Z, "elc_" + Z, H("f"), "org_neutral", "DISMISSED", H("n"))
SIG_DIGEST_VECTOR = "a3691bc6701ccde00105461c30098ba35b6ea23dbd64c58da2630fd2ccbb7344"
FINDING_DIGEST_VECTOR = "352c41ba0c51b025df9afd982471d2d9265a60ec0ce2174ba208c64f87197084"
REVIEW_DIGEST_VECTOR = "d77077ead937e26bb2c4d11638bdd560d59002dd5a4f28ec44e65dfcc238b9f4"
EIP191_PREFIX_HEX = "19457468657265756d205369676e6564204d6573736167653a0a3332"


def sig_vectors():
    d1 = proposal_digest(*SIG_DIGEST_VECTOR_INPUT)
    d2 = finding_digest(*FINDING_DIGEST_VECTOR_INPUT)
    d3 = review_digest(*REVIEW_DIGEST_VECTOR_INPUT)
    # layout sanity: 8 parts of 32 bytes for proposals, 7 for findings
    assert len(tag("PV2-PROPOSAL-v1") + idh("x") * 3 + u(1) + h32(H("t")) + idh("o") + u(1)) == 256
    assert (b"\x19Ethereum Signed Message:\n32").hex() == EIP191_PREFIX_HEX
    return d1, d2, d3


print("Hash primitives")
try:
    self_test()
    print("  ok   self-test")
    d1, d2, d3 = sig_vectors()
    for name, got, want in (("approval", d1, SIG_DIGEST_VECTOR), ("finding record", d2, FINDING_DIGEST_VECTOR),
                            ("review", d3, REVIEW_DIGEST_VECTOR)):
        if got != want:
            fail(f"{name} digest test vector mismatch: computed {got}")
        else:
            print(f"  ok   {name} digest vector", got[:16] + "…")
except AssertionError:
    fail("hashing reference implementation self-test")

# ---- 0. Duplicate keys (JSON and YAML parsers silently keep the last one) ----
class _DupKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader, node, deep=False):
    keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
    dups = sorted({str(k) for k in keys if keys.count(k) > 1})
    if dups:
        raise ValueError(f"duplicate YAML key(s) {dups} at line {node.start_mark.line + 1}")
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_DupKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _no_dup_json(pairs):
    keys = [k for k, _ in pairs]
    dups = sorted({k for k in keys if keys.count(k) > 1})
    if dups:
        raise ValueError(f"duplicate JSON key(s) {dups}")
    return dict(pairs)


def load_json(p):
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=_no_dup_json)


print("Duplicate keys / declarations")
dup_ok = True
for p in sorted(ROOT.rglob("*.json")):
    try:
        load_json(p)
    except ValueError as e:
        dup_ok = False
        fail(f"{p.relative_to(ROOT)}: {e}")
for p in sorted(ROOT.glob("*.yaml")):
    try:
        yaml.load(p.read_text(encoding="utf-8"), Loader=_DupKeyLoader)
    except ValueError as e:
        dup_ok = False
        fail(f"{p.name}: {e}")
ci = (ROOT / "chain-interface.md").read_text(encoding="utf-8")
sol = ci.split("```solidity", 1)[1].split("```", 1)[0]
for kind in ("function", "event"):
    names = re.findall(rf"\b{kind}\s+(\w+)\s*\(", sol)
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        dup_ok = False
        fail(f"chain-interface.md: duplicate Solidity {kind}(s) {dups}")
if sol.count("{") != sol.count("}") or sol.count("(") != sol.count(")"):
    dup_ok = False
    fail("chain-interface.md: unbalanced brackets in the Solidity interface")
if dup_ok:
    print("  ok   no duplicate keys; Solidity interface has unique functions/events and balanced brackets")

# Gateway ElectionChainState fields must be returned by the electionState / electionGovernance getters
def _getter_returns(name):
    m = re.search(rf"function\s+{name}\s*\([^)]*\)\s*external\s+view\s+returns\s*\((.*?)\);", sol, re.S)
    body = re.sub(r"//[^\n]*", "", m.group(1)) if m else ""
    return {w.split()[-1] for w in body.split(",") if w.strip()}
_ret = _getter_returns("electionState") | _getter_returns("electionGovernance")
_gw = yaml.safe_load((ROOT / "ledger-gateway.openapi.yaml").read_text(encoding="utf-8"))
_ecs = _gw["components"]["schemas"]["ElectionChainState"]["required"]
_alias = {"organizations": "orgIds", "operator_org": "operatorOrgId", "election_id": None, "block_number": None}
_missing = []
for f in _ecs:
    camel = _alias.get(f, re.sub(r"_(\w)", lambda x: x.group(1).upper(), f))
    if camel and camel not in _ret:
        _missing.append(f)
# Markdown tables: every row has as many cells as its header (extra cells are dropped when rendered)
def _cells(line):
    s = re.sub(r"`[^`]*`", "``", line.strip())
    return len([c for c in re.split(r"(?<!\\)\|", s.strip("|"))])
_tbl_bad = []
for md in [ROOT / "README.md", ROOT / "chain-interface.md", ROOT / "hashing.md",
           ROOT.parent / "docs" / "threat-model.md", ROOT.parent / "docs" / "test-plan.md"]:
    if not md.exists():
        continue
    head = None
    for n, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("|"):
            head = None
            continue
        if head is None:
            head = _cells(line)
        elif _cells(line) != head:
            _tbl_bad.append(f"{md.name}:{n}")
if _tbl_bad:
    fail(f"markdown table rows with a wrong cell count: {_tbl_bad}")
else:
    print("  ok   markdown tables have consistent cell counts")
if _missing:
    fail(f"ledger-gateway ElectionChainState fields not returned by any getter: {_missing}")
else:
    print("  ok   ElectionChainState fields map to electionState / electionGovernance return values")

# ---- 1. JSON Schemas ----
print("JSON Schemas")
schemas = {}
for p in sorted(ROOT.glob("*.schema.json")):
    s = json.loads(p.read_text(encoding="utf-8"))
    try:
        Draft202012Validator.check_schema(s)
        print("  ok  ", p.name)
    except Exception as e:  # noqa: BLE001
        fail(f"{p.name}: {e}")
    schemas[p.name.removesuffix(".schema.json")] = s

registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas.values())

# ---- 2. OpenAPI ----
print("OpenAPI")
for p in sorted(ROOT.glob("*.openapi.yaml")):
    try:
        spec = yaml.safe_load(p.read_text(encoding="utf-8"))
        validate_openapi(spec, base_uri=p.as_uri())
        print("  ok  ", p.name)
    except Exception as e:  # noqa: BLE001
        fail(f"{p.name}: {str(e).splitlines()[0]}")


# ---- 3. Examples ----
def validator_for(target):
    name, _, defs = target.partition(".")
    if name not in schemas:
        return None
    schema = {"$ref": f"{schemas[name]['$id']}#/$defs/{defs}"} if defs else schemas[name]
    return Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def semantic_ledger(doc, rel):
    problems = []
    fail = problems.append  # local: collect instead of failing immediately
    if doc.get("payload_hash") != Hc(doc["payload"]):
        fail(f"{rel}: payload_hash != Hc(payload)")
    if doc.get("time_precision") == "bucketed" and ts(doc["occurred_at"]) % doc["time_bucket_seconds"]:
        fail(f"{rel}: bucketed occurred_at not aligned to time_bucket_seconds")
    if doc["type"] == "CHECKPOINT_COMMITTED" and doc["payload"]["checkpoint"] != doc.get("checkpoint"):
        fail(f"{rel}: CHECKPOINT_COMMITTED payload.checkpoint != event checkpoint")
    if doc["type"] == "CHECKPOINT_COMMITTED" and len({t["table"] for t in doc["payload"]["tables"]}) != 6:
        fail(f"{rel}: CHECKPOINT_COMMITTED must list each of the 6 tables once")
    if doc["type"] == "BALLOT_RECEIVED":
        p = doc["payload"]
        want = Hc({"election_id": doc["election_id"], "nullifier_hash": p["nullifier_hash"], "ballot_hash": p["ballot_hash"]})
        if p["receipt_hash"] != want:
            fail(f"{rel}: receipt_hash formula mismatch")
    if doc["type"] == "ELECTION_CREATED":
        p = doc["payload"]
        for k in ("window_start", "window_end"):
            if ts(p[k]) % p["time_bucket_seconds"]:
                fail(f"{rel}: {k} not aligned to time_bucket_seconds")
        ids = [o["org_id"] for o in p["organizations"]]
        if ids != sorted(set(ids)):
            fail(f"{rel}: organizations must be sorted by org_id and unique")
        if p["checkpoint_interval_seconds"] % p["time_bucket_seconds"]:
            fail(f"{rel}: checkpoint_interval_seconds must be a multiple of time_bucket_seconds")
        if not 2 <= p["approval_threshold"] <= len(ids) - 1:
            fail(f"{rel}: approval_threshold must be between 2 and number of organizations - 1")
    if "received_at" in doc and ts(doc["received_at"]) < ts(doc["occurred_at"]):
        fail(f"{rel}: received_at earlier than occurred_at")
    if doc["type"] == "TALLY_PUBLISHED":
        p = doc["payload"]
        if p["invalid_ballots"] != len(p["invalid_ballot_hashes"]):
            fail(f"{rel}: invalid_ballots != len(invalid_ballot_hashes)")
        want = Hc({"election_id": doc["election_id"], "final_checkpoint": p["final_checkpoint"],
                   "results": sorted(p["results"], key=lambda r: r["candidate_id"]), "ballot_count": p["ballot_count"],
                   "invalid_ballots": p["invalid_ballots"], "invalid_ballot_hashes": sorted(p["invalid_ballot_hashes"]),
                   "excluded_ballots": p["excluded_ballots"], "ballot_set_root": p["ballot_set_root"]})
        if p["result_hash"] != want:
            fail(f"{rel}: result_hash formula mismatch")
        if sum(r["votes"] for r in p["results"]) != p["ballot_count"]:
            fail(f"{rel}: votes do not add up to ballot_count")
    return problems


def cross_ledger(docs):
    """Consistency across the valid ledger examples of ONE election (called once per election_id)."""
    # bucketed (voter) events at time t happened somewhere in [t, t+bucket): order them after exact events at t
    by_time = sorted(docs, key=lambda x: (ts(x[1]["occurred_at"]), x[1]["time_precision"] == "bucketed", x[1].get("seq", 0)))
    last_block = -1
    for rel, d in by_time:
        # only immediate anchors follow event time; batched anchors are committed later, after their batch closes
        b = d["anchor"].get("block_number") if d["anchor"].get("mode") == "immediate" else None
        if b is not None:
            if b < last_block:
                fail(f"{rel}: block_number decreases although occurred_at increases")
            last_block = b
    for source in ("core", "gateway"):
        seqs = [d["seq"] for _, d in by_time if d["source"] == source and "seq" in d]
        if seqs != sorted(seqs) or len(seqs) != len(set(seqs)):
            fail(f"seq of source {source} not strictly increasing in time order: {seqs}")
    cps = [(rel, d["checkpoint"]) for rel, d in by_time]
    for (r1, c1), (r2, c2) in zip(cps, cps[1:]):
        if c2 < c1:
            fail(f"checkpoint decreases in time order: {r1} ({c1}) -> {r2} ({c2})")
    created = [d for _, d in by_time if d["type"] == "ELECTION_CREATED"]
    bucket = created[0]["payload"]["time_bucket_seconds"] if created else None
    if bucket:
        for rel, d in by_time:
            if d["source"] == "core" and "received_at" in d:
                occ = ts(d["occurred_at"])
                release = occ if occ % bucket == 0 else (occ // bucket + 1) * bucket
                if ts(d["received_at"]) < release:
                    fail(f"{rel}: core event received before the end of its time bucket (release-unit rule)")
    # checkpoint granularity: inside one checkpoint interval, core events may span at most
    # 1 + (number of state transitions in that interval) checkpoints (STATE_CHANGE commits)
    interval = created[0]["payload"]["checkpoint_interval_seconds"] if created else None
    if interval:
        transitions = {"ROSTER_FROZEN", "ELECTION_OPENED", "ELECTION_CLOSED", "TALLY_PUBLISHED", "ELECTION_FINALIZED", "ELECTION_VOIDED"}
        windows = {}
        for _, d in by_time:
            if d["source"] == "core":
                w = windows.setdefault(int(ts(d["occurred_at"]) // interval), [set(), 0])
                w[0].add(d["checkpoint"])
                w[1] += d["type"] in transitions
        for cps_in, n_tr in windows.values():
            if len(cps_in) > 1 + n_tr:
                fail(f"checkpoints {sorted(cps_in)} inside one {interval}s interval with {n_tr} state transitions: finer than allowed")
    # effect events of an executed proposal must directly follow its ADMIN_ACTION_EXECUTED in core seq order
    core_seq = sorted((d for _, d in by_time if d["source"] == "core" and "seq" in d), key=lambda d: d["seq"])
    executed = {d["payload"]["proposal_id"]: d["seq"] for d in core_seq if d["type"] == "ADMIN_ACTION_EXECUTED"}
    effects = {"TOKEN_REVOKED", "ROSTER_AMENDED", "WINDOW_CHANGED", "ELECTION_VOIDED"}
    by_seq = {d["seq"]: d for d in core_seq}
    for d in core_seq:
        prop = d["payload"].get("proposal_id")
        if d["type"] in effects and prop in executed:
            prev = by_seq.get(d["seq"] - 1)
            ok = prev is not None and prev["payload"].get("proposal_id") == prop and (
                prev["type"] == "ADMIN_ACTION_EXECUTED" or prev["type"] in effects)
            if not ok or d["seq"] < executed[prop]:
                fail(f"{d['type']} seq {d['seq']}: effect does not directly follow ADMIN_ACTION_EXECUTED of its proposal")
    # checkpoint counts are cumulative: counts.X == sum of voter_events.X over all checkpoints <= k
    ccs = sorted((d for _, d in by_time if d["type"] == "CHECKPOINT_COMMITTED"), key=lambda d: d["payload"]["checkpoint"])
    run = {"TOKEN_USED": 0, "BALLOT_RECEIVED": 0}
    for d in ccs:
        for k in run:
            run[k] += d["payload"]["voter_events"][k]
        c = d["payload"]["counts"]
        if c["token_used"] != run["TOKEN_USED"] or c["ballots_received"] != run["BALLOT_RECEIVED"]:
            fail(f"CHECKPOINT_COMMITTED {d['payload']['checkpoint']}: counts not equal to cumulative voter_events")
        if c["token_used"] != c["credentials_issued"]:
            fail(f"CHECKPOINT_COMMITTED {d['payload']['checkpoint']}: token_used != credentials_issued (redeem is atomic)")
    tally = [d for _, d in by_time if d["type"] == "TALLY_PUBLISHED"]
    fin = [d for _, d in by_time if d["type"] == "ELECTION_FINALIZED"]
    if tally and fin and tally[0]["payload"]["result_hash"] != fin[0]["payload"]["result_hash"]:
        fail("ELECTION_FINALIZED.result_hash != TALLY_PUBLISHED.result_hash")


def cross_findings(ledger, submissions):
    """FINDING_RECORDED / FINDING_REVIEWED must carry Hc(submission) of the same finding."""
    by_id = {s["finding_id"]: s for s in submissions}
    for rel, d in ledger:
        if d["type"] in ("FINDING_RECORDED", "FINDING_REVIEWED"):
            s = by_id.get(d["payload"]["finding_id"])
            if s and d["payload"]["finding_hash"] != Hc(s):
                fail(f"{rel}: finding_hash != Hc(FindingSubmission example)")


print("Examples")
ledger_docs = []
finding_subs = []
for group, should_pass in (("valid", True), ("invalid", False)):
    for p in sorted((ROOT / "examples" / group).glob("*/*.json")):
        rel = p.relative_to(ROOT)
        v = validator_for(p.parent.name)
        if v is None:
            fail(f"{rel}: unknown target {p.parent.name}")
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        # most specific cause first (unevaluatedProperties errors are side effects of other failures)
        errs = sorted(v.iter_errors(doc), key=lambda e: (e.validator == "unevaluatedProperties", -len(e.path)))
        sem = semantic_ledger(doc, rel) if (p.parent.name == "ledger-events" and not errs) else []
        reasons = [e.message for e in errs] + sem
        if should_pass and reasons:
            fail(f"{rel}: {reasons[0][:140]}")
        elif not should_pass and not reasons:
            fail(f"{rel}: expected to be rejected but passed")
        else:
            print("  ok  ", rel, "" if should_pass else f"(rejected: {reasons[0][:70]})")
        if should_pass and p.parent.name == "ledger-events" and not reasons:
            ledger_docs.append((rel, doc))
        if should_pass and p.parent.name == "finding.FindingSubmission" and not errs:
            finding_subs.append(doc)

print("Cross-file checks")
for eid in sorted({d["election_id"] for _, d in ledger_docs}):
    cross_ledger([x for x in ledger_docs if x[1]["election_id"] == eid])
cross_findings(ledger_docs, finding_subs)
print("  done ", len(ledger_docs), "ledger examples")

print()
if errors:
    print(f"{len(errors)} problem(s)")
    sys.exit(1)
print("all contracts valid")
