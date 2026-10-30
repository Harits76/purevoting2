import sys
import os; H=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, H); sys.path.insert(0, H+"/../tests")
import setup_registry as s, ethsign
from chain import idh, encode
env, _ = s.read_env(os.path.expanduser("~/pv/demo.env"))
rpc = s.Rpc("http://127.0.0.1:8541"); cid = int(rpc("eth_chainId"), 16); c = env["CONTRACT_ADDRESS"]
def attempt(label, acct, sig, types, args):
    try:
        s.send(rpc, cid, acct, c, bytes.fromhex(s.sel(sig) + encode(types, args)))
        print(f"{label}: ACCEPTED (unexpected)")
    except RuntimeError as e:
        print(f"{label}: rejected -> {str(e).split('failed: ')[-1]}")
stranger = s.Account("0x" + "11" * 32)
gw = s.Account(env["GATEWAY_ACCOUNT_KEY"])
org = s.Account(env["ORG_OBSERVER_NODE_ACCOUNT_KEY"])
attempt("1 unregistered account sets operatorOrg", stranger, "setOperatorOrg(bytes32)", ["bytes32"], [idh("org_commission")])
attempt("2 org re-registers with another signer ", org, "registerOrgSigner(bytes32,address)", ["bytes32", "address"], [idh("org_observer"), stranger.address])
attempt("3 confirm a value nobody proposed       ", org, "confirmGatewayAccount(address)", ["address"], [stranger.address])
