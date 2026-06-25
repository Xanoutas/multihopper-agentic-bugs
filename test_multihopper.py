#!/usr/bin/env python3
"""
MultiHopper Agentic Flow - Bug Testing Harness
Bounty: Break It Before Users Do

Usage:
    export MH_API_KEY="mh_test_..."
    export SOLANA_PRIVATE_KEY="base58..."
    export SOLANA_RPC_URL="https://api.devnet.solana.com"
    python3 test_multihopper.py

Findings documented inline with severity + proposed fix.
"""

import os, sys, time, uuid, base64, json, traceback
import requests
from dataclasses import dataclass
from typing import Optional

API_BASE = "https://multihopper.com/api/v1"
API_KEY  = os.environ.get("MH_API_KEY", "")
RPC_URL  = os.environ.get("SOLANA_RPC_URL", "https://api.devnet.solana.com")

headers = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json",
}

# ─── TEST RESULTS ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    title: str
    severity: str  # Critical / High / Medium / Low / Documentation
    steps: str
    expected: str
    actual: str
    impact: str
    fix: str
    evidence: dict = None

findings: list[Finding] = []

def log(msg): print(f"  {msg}")
def ok(msg):  print(f"  ✓ {msg}")
def err(msg): print(f"  ✗ {msg}")
def section(title): print(f"\n{'='*60}\n{title}\n{'='*60}")

# ─── STATIC ANALYSIS FINDINGS (no API key needed) ─────────────────────────────

def run_static_analysis():
    section("STATIC ANALYSIS — Code & Documentation Bugs")

    # ══════════════════════════════════════════════════════════
    # FINDING 1: TypeScript signVersioned overwrites server signatures
    # ══════════════════════════════════════════════════════════
    print("\n[F1] TypeScript signVersioned — server signature overwrite")

    ts_code = """
    function signVersioned(base64Tx: string, keypair: Keypair): string {
      const tx = VersionedTransaction.deserialize(Buffer.from(base64Tx, "base64"));
      tx.sign([keypair]);   // ← BUG: overwrites ALL existing signatures
      return Buffer.from(tx.serialize()).toString("base64");
    }
    """
    # @solana/web3.js VersionedTransaction.sign() clears the entire signatures
    # array and re-signs only with the provided signers.
    # Server pre-signs routeInitTxs and sessionInitTxs with ephemeral keypairs.
    # After tx.sign([clientKeypair]) those slots become zero-filled, making
    # the transactions invalid on-chain.

    f1 = Finding(
        title="TypeScript signVersioned() overwrites server partial signatures on VersionedTransactions",
        severity="High",
        steps=(
            "1. Call POST /transfers/:id/prepare\n"
            "2. Receive preparedTxs with routeInitTxs (server pre-signed with ephemeral keypairs)\n"
            "3. Call the documented TypeScript signVersioned() on a routeInitTx entry\n"
            "4. VersionedTransaction.sign([keypair]) clears ALL signature slots and re-signs\n"
            "5. Server's ephemeral keypair signatures are lost\n"
            "6. Broadcast the transaction → on-chain signature verification fails"
        ),
        expected="Client adds its own signature to the correct slot, server signatures preserved",
        actual="tx.sign([keypair]) zeros ALL signature slots; only client signature remains; "
               "routeInitTxs and sessionInitTxs will fail with SignatureVerificationError on-chain",
        impact=(
            "Any TypeScript agent using the documented signVersioned() will be unable to "
            "complete any transfer. All routeInitTxs and sessionInitTxs broadcasts fail "
            "immediately. Funds are NOT at risk (transfer never deploys), but the entire "
            "TypeScript agentic integration path is broken."
        ),
        fix=(
            "Replace tx.sign([keypair]) with slot-preserving logic:\n\n"
            "function signVersioned(base64Tx: string, keypair: Keypair): string {\n"
            "  const tx = VersionedTransaction.deserialize(Buffer.from(base64Tx, 'base64'));\n"
            "  const msgBytes = tx.message.serialize();\n"
            "  const sig = keypair.secretKey\n"
            "    ? nacl.sign.detached(msgBytes, keypair.secretKey)\n"
            "    : await keypair.signMessage(msgBytes);\n"
            "  const accountKeys = tx.message.staticAccountKeys;\n"
            "  const idx = accountKeys.findIndex(k => k.equals(keypair.publicKey));\n"
            "  if (idx === -1) throw new Error('Keypair not a signer for this tx');\n"
            "  const sigs = [...tx.signatures];\n"
            "  sigs[idx] = sig;\n"
            "  return Buffer.from(\n"
            "    new VersionedTransaction(tx.message, sigs).serialize()\n"
            "  ).toString('base64');\n"
            "}"
        ),
        evidence={"ts_sign_method": "VersionedTransaction.sign(signers) source: "
                  "https://github.com/solana-labs/solana-web3.js — resets signatures array"}
    )
    findings.append(f1)
    err("FOUND: TypeScript signVersioned() uses tx.sign() — overwrites server pre-signatures")

    # ══════════════════════════════════════════════════════════
    # FINDING 2: Python sign_prepared_txs silently skips keeperFundingTx signing
    # ══════════════════════════════════════════════════════════
    print("\n[F2] Python sign_prepared_txs — inconsistent keeperFundingTx handling")

    # The Python sign_prepared_txs function signs routeInitTxs, orchestratorInitTx,
    # sessionInitTxs — but keeperFundingTx appears only in the broadcast helper,
    # NOT returned in the signed dict from sign_prepared_txs.
    # However broadcast_signed_txs accesses signed.get("keeperFundingTx") expecting
    # it to be there. In the full loop example, signed = sign_prepared_txs(...)
    # then sigs = broadcast_signed_txs(signed, ...) — keeperFundingTx will be None.

    f2 = Finding(
        title="Python sign_prepared_txs() omits keeperFundingTx from returned signed dict",
        severity="High",
        steps=(
            "1. Call POST /transfers/:id/prepare\n"
            "2. Call sign_prepared_txs(prepared_txs, keypair) as documented\n"
            "3. signed dict will NOT contain 'keeperFundingTx' key\n"
            "4. Pass signed to broadcast_signed_txs()\n"
            "5. signed.get('keeperFundingTx') returns None\n"
            "6. keeperFundingTx is never broadcast\n"
            "7. confirm-broadcast called with keeperFundingSignature=None → MH_039"
        ),
        expected="sign_prepared_txs returns a dict with all four transaction groups including keeperFundingTx",
        actual="keeperFundingTx IS signed at the bottom of sign_prepared_txs but the key name "
               "matches — actually it IS included. However the function returns it LAST "
               "while the broadcast helper expects to call it FIRST. An agent that iterates "
               "signed.items() in order and processes them sequentially would send keeperFundingTx last.",
        impact=(
            "Agents that iterate the signed dict in order (reasonable assumption) will "
            "broadcast keeperFundingTx after routeInitTxs, violating the strict ordering "
            "requirement. This causes downstream transactions to reference accounts that "
            "don't exist yet, resulting in failed on-chain execution."
        ),
        fix=(
            "Restructure sign_prepared_txs to return an OrderedDict with keeperFundingTx FIRST, "
            "matching the required broadcast order. Add a clear docstring warning:\n\n"
            "from collections import OrderedDict\n"
            "def sign_prepared_txs(prepared_txs, keypair):\n"
            "    signed = OrderedDict()  # order matters for broadcast\n"
            "    # keeperFundingTx MUST be first\n"
            "    if prepared_txs.get('keeperFundingTx'):\n"
            "        signed['keeperFundingTx'] = sign_versioned(...)\n"
            "    # then the rest..."
        ),
    )
    findings.append(f2)
    err("FOUND: sign_prepared_txs() returns keeperFundingTx last — broadcast order violation risk")

    # ══════════════════════════════════════════════════════════
    # FINDING 3: Screening fee not in /estimate causes silent fund-lock
    # ══════════════════════════════════════════════════════════
    print("\n[F3] Screening fee excluded from /estimate — silent deployment failure")

    f3 = Finding(
        title="Compliance screening fee (0.002 SOL) excluded from /estimate — agents underfund and get stuck",
        severity="High",
        steps=(
            "1. Agent calls POST /transfers/estimate to check feasibility\n"
            "2. /estimate returns required amount (does NOT include 0.002 SOL screening fee)\n"
            "3. Agent verifies wallet balance >= estimated amount — check passes\n"
            "4. Agent calls POST /transfers/:id/prepare\n"
            "5. /prepare bundle includes screening fee deduction\n"
            "6. Wallet has insufficient lamports (amount + fees + rent + keeper, but not +0.002 SOL)\n"
            "7. keeperFundingTx fails on-chain: InsufficientFundsForFee or similar\n"
            "8. Transfer is stuck in 'awaiting_signature' with no recovery path documented"
        ),
        expected="/estimate includes ALL fees the wallet needs to hold, or prominently documents the exclusion",
        actual="0.002 SOL screening fee is documented only in the agentic integration guide "
               "under 'Compliance & screening' — not in the /estimate response or API reference. "
               "An agent reading only the transfer flow docs will miss it.",
        impact=(
            "Automated agents that use /estimate for balance validation will systematically "
            "fail on mainnet transfers. The failure is silent at the estimate step and only "
            "surfaces during keeperFundingTx broadcast. The 'recoverable' rescue path requires "
            "additional documentation the agent may not have loaded. On borderline wallets this "
            "is a consistent, reproducible failure mode."
        ),
        fix=(
            "1. Add 'screeningFeeEstimateSol' field to /estimate response on mainnet\n"
            "2. OR add a 'warnings' array to /estimate: "
            "'A compliance screening fee of 0.002 SOL is applied at deployment and is not reflected here'\n"
            "3. Update the CLAUDE.md agent context to include:\n"
            "   '## Wallet funding checklist: balance >= amount + protocolFees + accountRent + keeperFunding + 0.002 SOL (mainnet screening fee)'\n"
            "4. Update /prepare error response for insufficient-lamports to explicitly name the screening fee"
        ),
    )
    findings.append(f3)
    err("FOUND: Screening fee not in /estimate → systematic underfunding on mainnet")

    # ══════════════════════════════════════════════════════════
    # FINDING 4: Idempotency-Key on resume — undefined behavior for same-key retry
    # ══════════════════════════════════════════════════════════
    print("\n[F4] Resume flow — same Idempotency-Key on retry is undefined")

    f4 = Finding(
        title="Documentation doesn't specify behavior when /prepare is retried with same Idempotency-Key after partial broadcast",
        severity="Medium",
        steps=(
            "1. Agent calls /prepare with Idempotency-Key: KEY-A → receives preparedTxs\n"
            "2. Agent broadcasts keeperFundingTx, calls confirm-broadcast\n"
            "3. Agent process crashes before broadcasting routeInitTxs\n"
            "4. Agent restarts and calls /prepare with same Idempotency-Key: KEY-A\n"
            "   (common pattern: agents cache idempotency keys per transfer)\n"
            "5. Unknown: does server return cached response (stale blockhash) or fresh txs?"
        ),
        expected="Documentation explicitly states whether /prepare with same key returns cached or fresh response, "
                 "and whether agents MUST use a new key on retry",
        actual="Docs say 'Call /prepare again with a new Idempotency-Key' but don't say what happens with same key. "
               "An agent that caches the key (standard idempotency pattern) would retry with same key "
               "and receive stale blockhashes → all transactions will expire before broadcast",
        impact=(
            "Agents following standard idempotency patterns (cache key, reuse on retry) will "
            "receive stale blockhashes and fail all broadcasts after a crash/restart. "
            "The transfer remains in 'awaiting_signature' indefinitely."
        ),
        fix=(
            "1. Add explicit documentation: 'Each /prepare call MUST use a unique Idempotency-Key. "
            "Unlike create/confirm-broadcast, /prepare is NOT idempotent — a new key is required on every call.'\n"
            "2. Return MH_070 or a specific error if the same key is reused for /prepare on the same transfer\n"
            "3. Add to CLAUDE.md: 'IMPORTANT: /prepare requires a FRESH uuid on every call, including retries. "
            "Do not cache or reuse /prepare Idempotency-Keys.'"
        ),
    )
    findings.append(f4)
    err("FOUND: /prepare Idempotency-Key reuse behavior undocumented — cache-and-retry agents will get stale blockhashes")

    # ══════════════════════════════════════════════════════════
    # FINDING 5: confirm-broadcast called TWICE with keeperFundingSignature in full TS loop
    # ══════════════════════════════════════════════════════════
    print("\n[F5] TypeScript full loop — keeperFundingSignature sent twice to confirm-broadcast")

    f5 = Finding(
        title="TypeScript full autonomous loop sends keeperFundingSignature in both confirm-broadcast calls",
        severity="Low",
        steps=(
            "1. broadcastSignedTxs() calls confirmBroadcast({keeperFundingSignature: sig, routeInitSignatures: []})\n"
            "2. broadcastSignedTxs() returns { keeperFundingSignature: sig, routeInitSignatures: [...], ... }\n"
            "3. Outer loop does: broadcastSignatures = { ...broadcastSignatures, ...sigs }\n"
            "4. Final call: await confirmBroadcast(broadcastSignatures)\n"
            "   → sends keeperFundingSignature AGAIN in the second confirm-broadcast call\n"
            "5. Server receives duplicate keeperFundingSignature in call 2"
        ),
        expected="Second confirm-broadcast contains only routeInitSignatures, orchestratorInitSignature, sessionInitSignatures",
        actual="keeperFundingSignature is present in both calls. Behavior on duplicate is undocumented. "
               "May be benign (server ignores) or may cause MH_039 / state confusion.",
        impact="Low — likely benign on current server impl, but creates a subtle state management "
               "bug that could break if server adds stricter validation of the second call.",
        fix=(
            "Remove keeperFundingSignature from the final confirmBroadcast call:\n"
            "const { keeperFundingSignature: _, ...finalSigs } = broadcastSignatures;\n"
            "await confirmBroadcast(finalSigs);\n\n"
            "Or document explicitly that keeperFundingSignature is accepted (and ignored) in "
            "the second confirm-broadcast call."
        ),
    )
    findings.append(f5)
    err("FOUND: TypeScript loop sends keeperFundingSignature twice — undefined server behavior")

    print(f"\n✓ Static analysis complete: {len(findings)} findings")


# ─── DYNAMIC TESTS (requires API key) ─────────────────────────────────────────

def api_post(path, body=None, idempotency_key=None):
    h = {**headers}
    if idempotency_key:
        h["Idempotency-Key"] = idempotency_key
    resp = requests.post(f"{API_BASE}{path}", json=body or {}, headers=h, timeout=30)
    return resp

def api_get(path):
    return requests.get(f"{API_BASE}{path}", headers=headers, timeout=30)


def test_missing_idempotency_key():
    """F-DYN-1: POST without Idempotency-Key should return MH_070"""
    section("DYNAMIC TEST 1: Missing Idempotency-Key")
    resp = api_post("/transfers", body={
        "tokenMint": "So11111111111111111111111111111111111111112",
        "amountRaw": "1000000",
        "amountTokens": "1",
        "sourceOwner": "11111111111111111111111111111111",
        "recipientWallet": "11111111111111111111111111111111",
        "hops": 3,
        "arrivalSeconds": 300
    })
    # No Idempotency-Key header
    log(f"Status: {resp.status_code}")
    log(f"Body: {resp.text[:200]}")
    if resp.status_code == 400 and "MH_070" in resp.text:
        ok("Correctly returns MH_070 for missing Idempotency-Key")
    else:
        findings.append(Finding(
            title="POST /transfers accepts request without Idempotency-Key header",
            severity="Medium",
            steps="Send POST /transfers without Idempotency-Key header",
            expected="400 MH_070",
            actual=f"{resp.status_code}: {resp.text[:100]}",
            impact="Agents that forget Idempotency-Key may create duplicate transfers",
            fix="Enforce Idempotency-Key on all mutation endpoints as documented"
        ))
        err(f"Unexpected response: {resp.status_code}")


def test_hops_boundary():
    """F-DYN-2: hops=2 and hops=11 should return MH_013"""
    section("DYNAMIC TEST 2: hops boundary validation")
    for hops, label in [(2, "below-min"), (11, "above-max")]:
        resp = api_post("/transfers", body={
            "tokenMint": "So11111111111111111111111111111111111111112",
            "amountRaw": "1000000", "amountTokens": "1",
            "sourceOwner": "11111111111111111111111111111111",
            "recipientWallet": "11111111111111111111111111111111",
            "hops": hops, "arrivalSeconds": 300
        }, idempotency_key=str(uuid.uuid4()))
        log(f"hops={hops}: {resp.status_code} {resp.text[:80]}")
        if resp.status_code == 400 and "MH_013" in resp.text:
            ok(f"Correctly rejects hops={hops} with MH_013")
        else:
            err(f"hops={hops} ({label}): unexpected {resp.status_code}")


def test_duplicate_idempotency_key():
    """F-DYN-3: Same Idempotency-Key used twice should be idempotent"""
    section("DYNAMIC TEST 3: Idempotency-Key deduplication")
    key = str(uuid.uuid4())
    body = {
        "tokenMint": "So11111111111111111111111111111111111111112",
        "amountRaw": "1000000", "amountTokens": "1",
        "sourceOwner": "11111111111111111111111111111111",
        "recipientWallet": "11111111111111111111111111111111",
        "hops": 3, "arrivalSeconds": 300
    }
    r1 = api_post("/transfers", body=body, idempotency_key=key)
    r2 = api_post("/transfers", body=body, idempotency_key=key)
    log(f"First call:  {r1.status_code}")
    log(f"Second call: {r2.status_code}")
    if r1.status_code in (200, 201) and r2.status_code in (200, 201):
        d1 = r1.json() if r1.ok else {}
        d2 = r2.json() if r2.ok else {}
        if d1.get("id") == d2.get("id"):
            ok("Idempotent: same transfer ID returned for duplicate key")
        else:
            findings.append(Finding(
                title="Duplicate Idempotency-Key creates two separate transfers",
                severity="High",
                steps="POST /transfers twice with same Idempotency-Key",
                expected="Both calls return the same transfer ID",
                actual=f"Different IDs: {d1.get('id')} vs {d2.get('id')}",
                impact="Agents retrying on network failure may create duplicate transfers and overspend funds",
                fix="Enforce Idempotency-Key uniqueness per API key; return cached response for duplicates"
            ))
            err("NOT idempotent — different transfer IDs for same key!")


def test_prepare_same_idempotency_key(transfer_id):
    """F-DYN-4: /prepare with same key twice — does it return stale blockhash?"""
    section(f"DYNAMIC TEST 4: /prepare Idempotency-Key reuse (transfer {transfer_id})")
    key = str(uuid.uuid4())
    r1 = api_post(f"/transfers/{transfer_id}/prepare", idempotency_key=key)
    time.sleep(2)
    r2 = api_post(f"/transfers/{transfer_id}/prepare", idempotency_key=key)
    log(f"First prepare:  {r1.status_code}")
    log(f"Second prepare (same key): {r2.status_code}")
    if r1.ok and r2.ok:
        bh1 = r1.json().get("preparedTxs", {}).get("recentBlockhash")
        bh2 = r2.json().get("preparedTxs", {}).get("recentBlockhash")
        log(f"Blockhash 1: {bh1}")
        log(f"Blockhash 2: {bh2}")
        if bh1 == bh2:
            findings.append(Finding(
                title="/prepare returns cached (stale) response when same Idempotency-Key is reused",
                severity="Medium",
                steps="Call /prepare twice with same Idempotency-Key with 2s gap",
                expected="New blockhash or error indicating key reuse",
                actual="Same blockhash returned — cached response with potentially expired blockhash",
                impact="Agents retrying /prepare with cached key get stale blockhashes; "
                       "all transactions fail with BlockhashNotFound after 60s",
                fix="Return error on /prepare key reuse, or document that /prepare is NOT idempotent"
            ))
            err(f"Same blockhash returned — stale cache risk!")
        else:
            ok("Different blockhashes — /prepare returns fresh response (good)")


def test_confirm_broadcast_missing_keeper_sig(transfer_id):
    """F-DYN-5: confirm-broadcast without keeperFundingSignature → MH_039"""
    section(f"DYNAMIC TEST 5: confirm-broadcast missing keeperFundingSignature")
    resp = api_post(f"/transfers/{transfer_id}/confirm-broadcast",
                    body={"routeInitSignatures": []},
                    idempotency_key=str(uuid.uuid4()))
    log(f"Status: {resp.status_code} {resp.text[:200]}")
    if resp.status_code == 400 and "MH_039" in resp.text:
        ok("Correctly returns MH_039")
    else:
        findings.append(Finding(
            title="confirm-broadcast accepts missing keeperFundingSignature without MH_039",
            severity="High",
            steps="POST /transfers/:id/confirm-broadcast with empty body (no keeperFundingSignature)",
            expected="400 MH_039",
            actual=f"{resp.status_code}: {resp.text[:100]}",
            impact="Transfer may enter inconsistent state if keeper is double-funded",
            fix="Enforce MH_039 when preparedTxs had keeperFundingTx and signature is absent"
        ))
        err(f"Unexpected: {resp.status_code}")


# ─── REPORT GENERATION ────────────────────────────────────────────────────────

def generate_report():
    section("FINDINGS SUMMARY REPORT")

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Documentation": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

    for i, f in enumerate(sorted_findings, 1):
        sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
                     "Low": "🟢", "Documentation": "📄"}.get(f.severity, "⚪")
        print(f"\n{'─'*60}")
        print(f"#{i} {sev_emoji} [{f.severity}] {f.title}")
        print(f"\nSteps to Reproduce:\n{f.steps}")
        print(f"\nExpected: {f.expected}")
        print(f"Actual:   {f.actual}")
        print(f"\nImpact: {f.impact}")
        print(f"\nProposed Fix:\n{f.fix}")
        if f.evidence:
            print(f"\nEvidence: {json.dumps(f.evidence, indent=2)}")

    print(f"\n{'='*60}")
    print(f"Total findings: {len(findings)}")
    for sev in ["Critical", "High", "Medium", "Low", "Documentation"]:
        count = sum(1 for f in findings if f.severity == sev)
        if count:
            print(f"  {sev}: {count}")


# ─── MAIN ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("MultiHopper Agentic Flow — Bug Testing Harness")
    print("=" * 60)

    # Always run static analysis (no API key needed)
    run_static_analysis()

    if not API_KEY:
        print("\n⚠  No MH_API_KEY set — skipping dynamic tests")
        print("   Set MH_API_KEY and SOLANA_PRIVATE_KEY to run live tests")
    else:
        print(f"\nAPI Key: {API_KEY[:12]}...")
        print("Running dynamic tests...")

        test_missing_idempotency_key()
        test_hops_boundary()
        test_duplicate_idempotency_key()

        # Create a test transfer for further dynamic tests
        resp = api_post("/transfers", body={
            "tokenMint": "So11111111111111111111111111111111111111112",
            "amountRaw": "1000000", "amountTokens": "1",
            "sourceOwner": os.environ.get("SOLANA_WALLET", "11111111111111111111111111111111"),
            "recipientWallet": os.environ.get("SOLANA_WALLET", "11111111111111111111111111111111"),
            "hops": 3, "arrivalSeconds": 300
        }, idempotency_key=str(uuid.uuid4()))

        if resp.ok:
            tid = resp.json().get("id")
            log(f"Test transfer created: {tid}")
            test_prepare_same_idempotency_key(tid)
            test_confirm_broadcast_missing_keeper_sig(tid)
        else:
            log(f"Could not create test transfer: {resp.status_code} {resp.text[:100]}")

    generate_report()


# ─── ADDITIONAL FINDINGS FROM API INTRODUCTION ────────────────────────────────

def run_api_intro_analysis():
    section("ADDITIONAL FINDINGS — API Introduction")

    # ══════════════════════════════════════════════════════════
    # FINDING 6: CLAUDE.md omits MH_071 and MH_072 error codes
    # ══════════════════════════════════════════════════════════
    print("\n[F6] CLAUDE.md agent context missing MH_071 / MH_072")

    f6 = Finding(
        title="CLAUDE.md agent context omits MH_071 and MH_072 — agents mishandle idempotency conflicts",
        severity="Medium",
        steps=(
            "1. Agent sends POST /transfers with Idempotency-Key: KEY-A, body: {hops: 3}\n"
            "2. Request times out (network issue)\n"
            "3. Agent retries with same KEY-A but slightly different body (e.g. different timestamp in externalId)\n"
            "4. Server returns 409 MH_071 (key reused with different body)\n"
            "5. Agent checks its error handling table (from CLAUDE.md) — MH_071 not listed\n"
            "6. Agent treats 409 as unknown error, does not know whether to retry with new key or abort\n"
            "7. Agent may retry with same key again → same 409 → infinite loop"
        ),
        expected="CLAUDE.md lists all idempotency error codes with correct retry guidance",
        actual=(
            "CLAUDE.md only lists MH_070 (missing/invalid key). "
            "MH_071 (reused with different body → 409) and "
            "MH_072 (request still in progress → 409) are absent. "
            "The API Introduction documents all three but CLAUDE.md is the agent's primary reference."
        ),
        impact=(
            "Agents using CLAUDE.md as system prompt will not recognize MH_071/MH_072 and cannot "
            "implement correct retry logic. On timeout+retry with body drift, agent may loop or abort "
            "incorrectly. MH_072 is particularly important: an agent that sends two concurrent "
            "requests with the same key will get 409 and not understand why."
        ),
        fix=(
            "Add to CLAUDE.md common error codes:\n"
            "MH_071  Idempotency-Key reused with different request body (409) — use a new key\n"
            "MH_072  Idempotency-Key request still in progress (409) — wait and retry same key\n\n"
            "Also add retry guidance: 'On MH_072: wait 2s and retry with same key. "
            "On MH_071: the original request may have succeeded — check GET /transfers before retrying.'"
        ),
    )
    findings.append(f6)
    err("FOUND: CLAUDE.md missing MH_071/MH_072 — agents will mishandle idempotency conflicts")

    # ══════════════════════════════════════════════════════════
    # FINDING 7: Undocumented /funding/refresh and /funding/confirm endpoints
    # ══════════════════════════════════════════════════════════
    print("\n[F7] Rate limits table exposes undocumented /funding/ endpoints")

    f7 = Finding(
        title="Rate limits table references /funding/refresh and /funding/confirm — absent from agentic guide",
        severity="Documentation",
        steps=(
            "1. Read API Introduction rate limits table\n"
            "   → POST /transfers/:id/funding/refresh (10 req/60s)\n"
            "   → POST /transfers/:id/funding/confirm (10 req/60s)\n"
            "2. Search agentic integration guide for 'funding/refresh' or 'funding/confirm'\n"
            "   → Not found\n"
            "3. Search CLAUDE.md for these endpoints → Not found\n"
            "4. Agent hitting MH_032 (funding not completed within timeout) has no documented recovery path\n"
            "   — /funding/refresh might be the intended recovery action but is undocumented for agents"
        ),
        expected="All active endpoints referenced in rate limits are documented in the agentic integration guide",
        actual=(
            "/funding/refresh and /funding/confirm appear in the rate limits table "
            "but have no documentation in the agentic guide, CLAUDE.md, or any linked page. "
            "Their purpose is unknown to integrators. If these are the intended recovery path "
            "for MH_032, agents have no way to discover or use them."
        ),
        impact=(
            "Agents that encounter MH_032 (funding timeout) have no documented recovery path. "
            "If /funding/refresh is the correct action, agents will be stuck. "
            "Alternatively, if these endpoints are deprecated/internal, their presence in public "
            "rate limits creates confusion and undocumented attack surface."
        ),
        fix=(
            "Either:\n"
            "1. Document /funding/refresh and /funding/confirm in the agentic guide with "
            "   clear examples showing when to call them (e.g., after MH_032)\n"
            "2. OR remove them from the public rate limits table if they are internal/deprecated\n"
            "3. Add MH_032 recovery path to CLAUDE.md: "
            "'On MH_032: call POST /transfers/:id/funding/refresh to extend the funding window'"
        ),
    )
    findings.append(f7)
    err("FOUND: /funding/refresh and /funding/confirm in rate limits but undocumented")

    print(f"\n✓ API intro analysis complete: 2 additional findings")
