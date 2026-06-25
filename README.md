# MultiHopper Agentic Flow — Bug Findings

Bounty submission for [Break It Before Users Do: MultiHopper Agentic Flow Bugs & Fixes](https://earn.superteam.fun)

## Summary

7 findings from static analysis of the MultiHopper agentic integration documentation and code examples.

| # | Severity | Title |
|---|---|---|
| F1 | 🟠 High | TypeScript `signVersioned()` overwrites server partial signatures |
| F2 | 🟠 High | Python `sign_prepared_txs()` returns `keeperFundingTx` last — broadcast order violation |
| F3 | 🟠 High | Compliance screening fee excluded from `/estimate` — silent mainnet failure |
| F4 | 🟡 Medium | `/prepare` Idempotency-Key reuse behavior undocumented |
| F5 | 🟢 Low | TypeScript full loop sends `keeperFundingSignature` twice |
| F6 | 🟡 Medium | `CLAUDE.md` omits MH_071 / MH_072 error codes |
| F7 | 📄 Documentation | `/funding/refresh` and `/funding/confirm` undocumented |

## Files

- [`SUBMISSION.md`](./SUBMISSION.md) — Full findings report with reproduction steps and fixes
- [`test_multihopper.py`](./test_multihopper.py) — Python test harness (static + dynamic tests)

## Running the tests

```bash
pip install requests

# Static analysis only (no API key needed)
python3 test_multihopper.py

# Full dynamic tests
export MH_API_KEY="mh_test_..."
export SOLANA_PRIVATE_KEY="..."
export SOLANA_RPC_URL="https://api.devnet.solana.com"
python3 test_multihopper.py
```
