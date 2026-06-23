# nmchain

## Sponsor NeuralMimicry

`nmchain` is an open-source private permissioned blockchain providing a tamper-evident, append-only audit ledger for identity, payment, and token events across the NeuralMimicry platform. NeuralMimicry is an independent open-source initiative and we rely on community support to sustain this work.

**[☕ Support us on Crowdfunder](https://www.crowdfunder.co.uk/p/qr/aWggxwPW?utm_campaign=sharemodal&utm_medium=referral&utm_source=shortlink)**

---

`nmchain` is a private, permissioned Rust blockchain service for NeuralMimicry account identity, payment settlement, token minting, reservation, debit, refund, and cash-out records.

## What it does

- Stores an append-only block log in `data/blocks.jsonl`.
- Seals every accepted business event into a signed block.
- Replays blocks on startup to rebuild account state.
- Exposes HTTP APIs for:
  - identity upsert
  - login observation
  - payment capture
  - token mutation (`topup`, `grant`, `refund`, `cashout`, `reserve`, `release`, `debit`, `sync`)
  - account snapshots and ledger history

## Environment

- `NMCHAIN_LISTEN` = bind address, default `127.0.0.1:9080`
- `NMCHAIN_DATA_DIR` = chain data directory, default `data`
- `NMCHAIN_CHAIN_ID` = logical chain id, default `neuralmimicry-private-chain`
- `NMCHAIN_VALIDATOR_ID` = local validator id, default `nm-validator-1`
- `NMCHAIN_VALIDATOR_KEY_PATH` = signing-key file path, default `${NMCHAIN_DATA_DIR}/validator.key.json`
- `NMCHAIN_APP_TOKENS` = comma-separated bearer tokens, e.g. `refiner=secret1,aarnn=secret2,website=secret3`

If `NMCHAIN_APP_TOKENS` is omitted the API runs in open development mode.

## Run

```bash
cargo run
```

## Example

```bash
curl -s \
  -H 'Authorization: Bearer secret1' \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id": "topup-1",
    "user_id": "alice",
    "tokens": 250,
    "amount_minor": 2500,
    "currency": "GBP",
    "provider": "cardstream",
    "payment_id": "pay_123",
    "checkout_flow": "hosted",
    "meta": {"source": "portal"}
  }' \
  http://127.0.0.1:9080/api/events/payment
```
