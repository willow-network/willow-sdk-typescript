# Changelog

All notable changes to this package are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
package adheres to [Semantic Versioning](https://semver.org/).

<!-- REMOVE-ON-PUBLISH: on release, change "[0.1.0] - Unreleased" to "[0.1.0] - <date>", drop "Unreleased", and delete the README pre-publish git-install note (README.md "## Installation"). -->
## [0.1.0] - Unreleased

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
