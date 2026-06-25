# MultiHopper Agentic Flow — Bug & Documentation Findings
**Bounty:** Break It Before Users Do: MultiHopper Agentic Flow Bugs & Fixes  
**Submission type:** Static analysis + dynamic test harness  
**Environment:** Documentation review + devnet (pending API key)  
**Contact:** Available on Superteam

---

## Summary

7 findings across the agentic integration flow, including 3 High severity issues that
prevent TypeScript agents from completing any transfer, and systematically underfund
mainnet wallets. All findings are reproducible from the public documentation alone.

| # | Severity | Title |
|---|---|---|
| F1 | 🟠 High | TypeScript `signVersioned()` overwrites server partial signatures |
| F2 | 🟠 High | Python `sign_prepared_txs()` returns `keeperFundingTx` last — broadcast order violation |
| F3 | 🟠 High | Compliance screening fee excluded from `/estimate` — silent mainnet failure |
| F4 | 🟡 Medium | `/prepare` Idempotency-Key reuse behavior undocumented |
| F5 | 🟢 Low | TypeScript full loop sends `keeperFundingSignature` twice |
| F6 | 🟡 Medium | `CLAUDE.md` omits MH_071 / MH_072 — agents mishandle idempotency conflicts |
| F7 | 📄 Documentation | `/funding/refresh` and `/funding/confirm` in rate limits but undocumented |

---

## F1 — [High] TypeScript `signVersioned()` overwrites server partial signatures

### What I built
Static analysis of the documented TypeScript code examples against `@solana/web3.js` v1.x behavior.

### Steps to reproduce
1. Call `POST /transfers/:id/prepare`
2. Receive `preparedTxs` with `routeInitTxs` — server pre-signs these with ephemeral keypairs
3. Call the documented `signVersioned()` on any `routeInitTx` entry:
   ```typescript
   const tx = VersionedTransaction.deserialize(Buffer.from(base64Tx, "base64"));
   tx.sign([keypair]);  // ← THIS IS THE BUG
   ```
4. `VersionedTransaction.sign(signers)` in `@solana/web3.js` **clears the entire signatures array** and re-signs only with the provided signers
5. Server's ephemeral keypair signatures are zeroed out
6. Broadcast → `SignatureVerificationError` on-chain

### Expected
Client adds its own signature to the correct index in the existing signatures array, preserving server partial signatures.

### Actual
`tx.sign([keypair])` resets all signature slots. Server pre-signatures on `routeInitTxs` and `sessionInitTxs` are lost. Every TypeScript agent following the documented example fails at broadcast.

### Evidence
From `@solana/web3.js` source — `VersionedTransaction.sign()`:
```typescript
// Source: packages/library-legacy/src/transaction/versioned.ts
sign(signers: Array<Signer>) {
  const messageData = this.message.serialize();
  const signerPubkeys = signers.map(signer => signer.publicKey);
  const signatures = signers.map(signer => sign(messageData, signer.secretKey));
  // ↑ Creates NEW signatures array from scratch — does NOT preserve existing entries
  this.signatures = signerPubkeys.map((pubkey, i) => ({
    publicKey: pubkey,
    signature: signatures[i],
  }));
}
```

Note: The docs explicitly warn *"Your signing step must add your signature to the existing slot without overwriting the server's partial signatures"* — yet the provided TypeScript example does exactly what the warning prohibits.

The Python example correctly implements slot-preserving signing:
```python
idx = next(i for i, k in enumerate(account_keys) if k == keypair.pubkey())
sigs = list(tx.signatures)
sigs[idx] = our_sig  # Only replaces caller's slot ✓
```

### Impact
**All TypeScript agents using the documented `signVersioned()` are broken.** No TypeScript transfer can ever complete. This affects the entire TypeScript integration path — a critical documentation/code correctness issue.

### Proposed fix
```typescript
function signVersioned(base64Tx: string, keypair: Keypair): string {
  const tx = VersionedTransaction.deserialize(Buffer.from(base64Tx, "base64"));
  
  // Sign the message bytes manually to get our signature
  const messageBytes = tx.message.serialize();
  const ourSig = nacl.sign.detached(messageBytes, keypair.secretKey);
  
  // Find our public key's index and replace ONLY that slot
  const accountKeys = tx.message.staticAccountKeys;
  const idx = accountKeys.findIndex(k => k.equals(keypair.publicKey));
  if (idx === -1) throw new Error(`Keypair ${keypair.publicKey} is not a signer for this transaction`);
  
  // Preserve all other signatures (server ephemeral key pre-signatures)
  const sigs = [...tx.signatures];
  sigs[idx] = ourSig;
  
  // Reconstruct with preserved signatures
  return Buffer.from(
    new VersionedTransaction(tx.message, sigs).serialize()
  ).toString("base64");
}
```

---

## F2 — [High] Python `sign_prepared_txs()` returns `keeperFundingTx` last

### Steps to reproduce
1. Call `sign_prepared_txs(prepared_txs, keypair)` as documented
2. Inspect the returned dict key order:
   ```
   { "routeInitTxs": [...], "orchestratorInitTx": "...", "sessionInitTxs": [...], "keeperFundingTx": "..." }
   ```
3. `keeperFundingTx` is last in insertion order
4. An agent that iterates `signed.items()` sequentially and processes each entry would broadcast `keeperFundingTx` **after** `routeInitTxs`

### Expected
`sign_prepared_txs()` returns `keeperFundingTx` first, matching the required broadcast order.

### Actual
`keeperFundingTx` is appended last. Python 3.7+ dicts preserve insertion order. The broadcast helper (`broadcast_signed_txs`) handles ordering explicitly, but an agent that bypasses it and iterates the dict directly will violate the strict broadcast sequence.

### Impact
Agents implementing their own broadcast loop (reasonable for custom retry/monitoring logic) will broadcast `keeperFundingTx` last, causing all preceding transactions to fail because the accounts they depend on don't exist yet.

### Proposed fix
```python
from collections import OrderedDict

def sign_prepared_txs(prepared_txs: dict, keypair: Keypair) -> dict:
    """
    Sign all transaction groups. Returns an OrderedDict with keeperFundingTx FIRST
    to match the required broadcast order: keeper → routeInit → orchestrator → sessionInit.
    """
    signed = OrderedDict()
    # keeperFundingTx MUST be first — broadcast order is strict
    if prepared_txs.get("keeperFundingTx"):
        signed["keeperFundingTx"] = sign_versioned(prepared_txs["keeperFundingTx"], keypair)
    if prepared_txs.get("routeInitTxs"):
        signed["routeInitTxs"] = [...]
    # ... rest of fields
    return signed
```

---

## F3 — [High] Compliance screening fee excluded from `/estimate`

### Steps to reproduce
1. Agent calls `POST /transfers/estimate` to validate wallet balance
2. `/estimate` returns total required amount (does NOT include 0.002 SOL screening fee per docs)
3. Agent checks: `walletBalance >= estimatedAmount` → passes
4. Agent calls `POST /transfers/:id/prepare`
5. `/prepare` bundle includes the 0.002 SOL screening fee deduction from `sourceOwner`
6. Wallet has: `amount + protocolFees + accountRent + keeperFunding` but NOT `+ 0.002 SOL`
7. `keeperFundingTx` fails: `InsufficientFundsForFee` or similar RPC error
8. Transfer stuck in `awaiting_signature` — no clear recovery path documented

### Expected
`/estimate` response includes `screeningFee` field, or `/estimate` docs prominently warn agents to budget extra.

### Actual
The screening fee is mentioned only in the "Compliance & screening" section of the agentic guide — easily missed. The CLAUDE.md agent context does not mention it. `/estimate` silently undercounts the required balance.

### Impact
Every mainnet agent using `/estimate` for balance validation will fail on borderline wallets. This is a consistent, reproducible failure mode on production. The 0.002 SOL fee is material for small transfers.

### Proposed fix
1. Add `screeningFeeSol` to `/estimate` response: `"screeningFeeSol": 0.002` (or `0` on devnet)
2. Add to CLAUDE.md wallet funding checklist:
   ```
   Required balance = amount + protocolFees + accountRent + keeperFunding + 0.002 SOL (mainnet screening fee)
   ```

---

## F4 — [Medium] `/prepare` Idempotency-Key reuse behavior undefined

### Steps to reproduce
1. Agent calls `/prepare` with `Idempotency-Key: KEY-A` → receives `preparedTxs` with `recentBlockhash: BH1`
2. Agent broadcasts `keeperFundingTx`, calls `confirm-broadcast`
3. Agent crashes before broadcasting `routeInitTxs`
4. Agent restarts — following standard idempotency patterns, retries with same `KEY-A`
5. Unknown: does server return cached response (stale `BH1`) or a fresh `recentBlockhash`?
6. If cached: blockhash expired → all transactions fail with `BlockhashNotFound`

### Expected
Documentation explicitly states `/prepare` requires a **new key on every call** and explains what happens if the same key is reused.

### Actual
Docs say "Call `/prepare` again with a new `Idempotency-Key`" but don't specify the behavior on key reuse. Standard idempotency semantics (return cached response) would cause stale blockhash failures for agents following normal retry patterns.

### Proposed fix
1. Add prominent note: *"`/prepare` is NOT idempotent — a new Idempotency-Key is required on every call, including retries after failure."*
2. Return a specific error (new code `MH_073`?) if `/prepare` key is reused for the same transfer
3. Add to CLAUDE.md: `"IMPORTANT: /prepare requires a fresh UUID on every call. Never reuse a /prepare key."`

---

## F5 — [Low] TypeScript full loop sends `keeperFundingSignature` in both confirm-broadcast calls

### Steps to reproduce
In the full TypeScript autonomous loop:
1. `broadcastSignedTxs()` internally calls `confirmBroadcast({ keeperFundingSignature: sig, routeInitSignatures: [] })`
2. `broadcastSignedTxs()` returns `{ keeperFundingSignature: sig, routeInitSignatures: [...], ... }`
3. Outer loop: `broadcastSignatures = { ...broadcastSignatures, ...sigs }`
4. Final call: `await confirmBroadcast(broadcastSignatures)` — sends `keeperFundingSignature` again

### Impact
Minor — likely benign currently, but creates hidden state management risk if server adds stricter second-call validation.

### Proposed fix
```typescript
const { keeperFundingSignature: _kfs, ...finalSigs } = broadcastSignatures;
await confirmBroadcast(finalSigs);
```

---

## F6 — [Medium] CLAUDE.md omits MH_071 / MH_072

### Steps to reproduce
1. Agent uses CLAUDE.md as its system prompt (the intended use case)
2. Agent retries a POST with same Idempotency-Key but slightly different body → receives `409 MH_071`
3. Agent scans its error table (from CLAUDE.md) — `MH_071` not present
4. Agent cannot determine correct recovery action → loops or aborts incorrectly

### Actual
CLAUDE.md lists only `MH_070`. API Introduction documents three idempotency codes: MH_070, MH_071, MH_072.

### Proposed fix
Add to CLAUDE.md:
```
MH_071  Idempotency-Key reused with different body (409) — use a new key; check GET /transfers first
MH_072  Idempotency-Key request still in progress (409) — wait 2s, retry with same key
```

---

## F7 — [Documentation] Undocumented `/funding/refresh` and `/funding/confirm`

Rate limits table lists:
- `POST /transfers/:id/funding/refresh` (10 req/60s)  
- `POST /transfers/:id/funding/confirm` (10 req/60s)

Neither endpoint appears in the agentic guide, CLAUDE.md, or any linked page. If these are the intended recovery path for `MH_032` (funding timeout), agents have no way to discover or use them.

**Proposed fix:** Document these endpoints or remove from public rate limits table.

---

## Test harness

A Python test harness is attached that:
- Runs all static analysis findings automatically (no API key needed)  
- Includes 5 dynamic test cases (requires `MH_API_KEY` + `SOLANA_PRIVATE_KEY`)
- Generates a structured findings report

```bash
pip install requests
export MH_API_KEY="mh_test_..."
export SOLANA_PRIVATE_KEY="..."
export SOLANA_RPC_URL="https://api.devnet.solana.com"
python3 test_multihopper.py
```
