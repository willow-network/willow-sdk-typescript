# Changelog

All notable changes to this package are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
package adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `WillowAuth.signRequestWithNonce(method, pathAndQuery, body?)` and
  `WillowAuth.getSignedHeaders(method, pathAndQuery, body?)`: the nonce form
  of request signing, the only form that carries a DID's read rights (see the
  README's "Request signing").
- `signedRequestMessage`, `legacyRequestMessage`, `newRequestNonce`, and
  `SIGNED_REQUEST_VERSION`, for building and checking request signatures.
- `signSecp256k1` and `verifySecp256k1`, which sign and verify as the chain
  does.
- `resolveRequest(baseURL, path)`, which gives the URL `fetch` sends and the
  request target the API receives, and `HttpRequestOptions.sign`, a
  per-request signer run once the URL and body are final.
- Types: `NonceSignedRequestHeaders`, `SignedRequestHeaders`,
  `SignRequestOptions`, `RequestSigner`, and `ResolvedRequest`.
- `storeDataSignMessage`, `storeFileManifestSignMessage`, and
  `deleteFileManifestSignMessage`, which return the message a data write, a
  file manifest, or a file delete signs (see the README's "Data and file
  write signing"), and the `StoreFileManifestTx` and `DeleteFileManifestTx`
  types they take.

### Changed

- With an identity set, `GET /data/:sg/:key`, `GET /proof/:sg/:key`, and
  `POST /query/:sg`, `/sql/:sg`, and `/graphql/:sg` sent to the API are
  nonce-signed over the path and query as sent and the exact body.
  `getProof` is now signed.
- Other signed requests keep the older `{METHOD}:{PATH}:{TIMESTAMP}` form,
  now over the path as sent (percent-encoded) without its query string, as
  the server verifies it. `getKeyGrantProof` is now signed in this form.
- **secp256k1 request signatures** are ECDSA over the Keccak-256 of the
  message, lower-S, sent as `0x`-prefixed 64-byte `r || s`. They were EIP-191
  signatures of a hash, 65 bytes, without a prefix, which the server does not
  verify.
- **`createDidFromWallet` and `createDidFromPublicKey`** publish a secp256k1
  key in its 33-byte compressed form. The chain cannot parse the 64-byte
  `x || y` form.
- `client.eth` and `client.verifiableRpc` throw `INDEXER_URL_REQUIRED` when
  no `indexerUrl` is configured, instead of sending `/verifiable-rpc/*` to the
  API, which doesn't serve it.
- `WillowClient.init()` reads the key id from the API's `public_keys`.
- **Data and file writes sign their nonce and every field.** StoreData
  (`storeData`, `client.store`), StoreFileManifest (`storeFileManifest`,
  `files.upload`), and DeleteFileManifest (`deleteFileManifest`,
  `files.delete`) are signed over labelled lines: the kind, then the
  subgrove, key, owner, the SHA-256 of the data bytes sent (StoreData) or
  every manifest field (StoreFileManifest), and the nonce. They were signed
  over `{subgrove}:{key}:{data}`, `store_file:…`, and `delete_file:…`. The
  SDK refuses to sign one whose subgrove id, key, owner DID, filename, or
  content type holds a `\n` (0x0A), or whose nonce, size, or count is not a
  non-negative safe integer (it refuses such a number rather than round it).
  A write the chain refuses in its block after its signature and nonce
  verify still spends its nonce; a retry signs again under the next free
  nonce.
- A file manifest's `contentHash` and `chunkMerkleRoot` must be 32 bytes of
  hex; any other length throws `INVALID_DIGEST` before the transaction is
  sent.

### Removed

- `WillowAuth.getAuthParams()`. It built a `?did=` query parameter the server
  ignores.

## [0.1.0] - 2026-06-11

First npm release. Everything below describes changes made while preparing
the previously git-only SDK for publication; if you consumed the SDK from
git, read the breaking changes carefully.

### Breaking changes (relative to the pre-release git version)

- **Proof verification binds data to the proof.** `verifyQueryProof` used to
  accept a `documents` parameter and ignore it, so a server could pair a
  valid proof with unrelated data. Every document must now deep-equal a value
  the proof commits to, and `verifyItemProof` likewise binds the supplied
  `value` (not just key and path). Responses that previously "verified" with
  uncommitted data now throw.
- **`configureProofVerification` removed.** The hidden mutable module-global
  is gone; pass options explicitly via `WillowConfig.proofVerificationOptions`
  or the per-call `options` argument.
- **`registerSubgrove` returns the consensus `BroadcastResult`** (txHash,
  height, rawLog) instead of fabricating a `DatasetRegistration` with
  wall-clock timestamps.
- **`waitForTransaction` throws `ConsensusError` (`TX_CONFIRM_TIMEOUT`) on
  timeout** instead of resolving with status `PENDING`.
- **Devnet port derivation no longer applies to remote hosts.** The
  apiUrl→CometBFT-RPC port heuristic only runs for `localhost`/`127.0.0.1`;
  any other host requires `consensusRpcUrl`, and operations that need
  CometBFT RPC throw `CONSENSUS_RPC_URL_REQUIRED` instead of silently
  pointing at the API server.
- **The SDK is silent by default.** All internal `console.*` logging was
  replaced by an injectable logger (`WillowConfig.logger`); pass
  `consoleLogger` to restore output.
- **Root barrel slimmed.** Generic utils (`sleep`, `retry`, `chunk`,
  `generateId`), the computed-fields `export default` object, and the unused
  `globalComputedFieldRegistry` are no longer exported. The grovedb barrel
  also dropped dead types (`ProofVerificationResult` collision, `QueryItem`)
  and flattened `Reference` paths to `Uint8Array[]`.
- **Node >= 18 required** (the SDK uses the global `fetch`; the previous
  `>=16` claim was wrong).

### Deprecated (kept as working aliases)

- `extractRootHashFromProof` → renamed `computeProofRootHash` (the old name
  suggested parsing; it always performed full verification).
- `verifyProofAdvanced` → use `GroveDBProofVerifier`, which carries options
  on the instance and returns the same structured result.
- `registerDataset` / `RegisterDatasetRequest` → `registerSubgrove` /
  `RegisterSubgroveRequest` ("subgrove" is the on-chain term).
- `WillowAuth.getDid_` → `getDidDocument`.
- Positional signing parameters on `ConsensusClient` methods → the new
  `Signer` options object (`{ privateKey, publicKeyId, signFunction }`);
  `storeFileManifest`'s 13 positional params collapse to
  `(StoreFileManifestFields, Signer)`.

### Fixed

- **Transaction broadcast unified on `POST /tx/submit`** (the API server's
  single tx ingress, which bincode-encodes for the chain). Privacy
  transactions previously pushed base64(JSON) directly at CometBFT and could
  never decode; file-manifest transactions POSTed to a nonexistent
  `/broadcast_tx` endpoint (always 404).
- **File requests are now signed per-request** with their real method+path.
  Previously a fixed thunk always signed `GET:/files`, so every other file
  request carried a wrong signature.
- **GroveDB decoders hardened against malformed input**: bounds-checked
  reads (truncated buffers used to fabricate empty nodes via NaN
  arithmetic), varint decoding without 32-bit truncation (values >= 2^31
  were silently corrupted) plus u64 range enforcement, and layer-proof
  nesting capped at 64 to prevent crafted-proof stack overflow. Malformed
  proofs now fail with clean typed errors.
- **eth-state browser safety**: removed unguarded `Buffer` usage (threw
  `ReferenceError` in browsers) and fixed storage-slot math that truncated
  slot indexes to one byte; slots are now full 32-byte big-endian words.
  `withMode` returns a new instance instead of mutating shared state.
- **`isValidDid` accepts hyphenated DIDs** (e.g. `did:willow:devnet-test`)
  and optional extra segments.
- `./grovedb` subpath now actually resolves (README documented it before the
  exports map entry existed), with per-condition `.d.mts`/`.d.ts` types.

### Added

- Injectable logging: `WillowLogger` interface, `silentLogger` (default),
  `consoleLogger`, threaded through `WillowClient`, `WillowData`,
  `ConsensusClient`, `LightClient`, and `HeaderVerifier`.
- `WillowConfig.lightClient` (`WillowLightClientOptions`) to override the
  auto-created light client's chain id, endpoints, and consensus thresholds
  (previously hardcoded single-node devnet defaults).
- `WillowConfig.webSocket`: injectable WebSocket implementation for GraphQL
  subscriptions (defaults to `globalThis.WebSocket`; pass `ws` on Node < 22).
  `subscribe()` throws a typed `WEBSOCKET_UNAVAILABLE` error when neither
  exists.
- `GroveDBProofVerifier`: instance-scoped verification options with
  structured `{ valid, rootHash?, error? }` results.
- Typed error hierarchy: `ConsensusError`, `LightClientError`, and
  `ManifestValidationError` extend `WillowError`; `HttpClient`/`HttpError`
  exported as part of the thrown-error surface; file/privacy/erc8004 modules
  throw coded `WillowError`s instead of bare `Error`s.

### Changed

- **axios replaced with a zero-dependency typed `fetch` wrapper** — the SDK
  now has three runtime dependencies (`@noble/ciphers`, `@noble/curves`,
  `@noble/hashes`) plus `ethers`.
- Light-client documentation now states the actual trust model: the
  root-hash path fetches `app_hash` from the configured RPC endpoint(s)
  without commit/header verification, and `verifyHeader` is `@experimental`
  (CometBFT signs protobuf `CanonicalVote`; the current canonical-JSON
  sign-bytes never validate real commits).
- Packaging: `publishConfig.access=public`, per-condition `exports` types,
  `sideEffects: false`, sourcemaps dropped from the tarball (380K → 180K),
  unused `blake3` dependency removed, `ws` override for local dev (the SDK
  repo's own `npm audit --omit=dev` is clean), yarn.lock deleted (npm
  canonical). Note: `overrides` does not reach consumers — see *Known issues*
  in the README for the transitive `ws` advisory inherited from `ethers`.
- CI: `npm ci` + build + test on a Node 18/20/22 matrix (the lockfile was
  previously never exercised).

### Tests

- 430+ passing (plus 11 skipped live-network tests): new
  coverage for the files, privacy, and erc8004 modules; proof/document
  binding accept/reject cases; malformed-proof truncation sweeps; varint
  bounds; recursion-cap rejection.
- The partial-proof regression fixture is now produced by a committed Rust
  generator pinned to the chain's GroveDB release, replacing a fixture
  captured from a live partner indexer.
