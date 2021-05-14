# Changelog

## [v0.7.0](http://github.com/kinecosystem/kin-go/releases/tag/v0.6.0)
- Remove Stellar (Kin 2 & Kin 3) support
    - Only Kin 4 and v4 Agora APIs are supported
    - Removed `WithKinVersion`, `WithWhitelister` and `WithDesiredKinVersion` client options
    - `Channel` has been removed from `Payment` and `EarnBatch`
    - `Envelope` and `TxHash()` have been removed from `SignTransactionRequest`
- CreateAccount now creates associated token accounts
- Add sender create support for `SubmitPayment`
- Add `MergeTokenAccounts` to `Client`
- Add create account webhook support
- Add creation parsing to `SignTransactionRequest` request
- `SignTransactionResponse.Sign` now signs Solana transactions

## [v0.6.0](http://github.com/kinecosystem/kin-go/releases/tag/v0.6.0)
- Don't retry on precondition failed
- Add `GetEvents` to internal client

## [v0.5.0](http://github.com/kinecosystem/kin-go/releases/tag/v0.5.0)
- Expose `RequestAirdrop` on `Client` for Kin 4

## [v0.4.0](http://github.com/kinecosystem/kin-go/releases/tag/v0.4.0)
- Moved Go client SDK into this repo
- `PublicKey`, `PrivateKey`, `KinVersion`, webhook and kin/quark conversion utils are now located in https://github.com/kinecosystem/agora-common

Note: previous versions of this SDK can be found in https://github.com/kinecosystem/agora-internal
