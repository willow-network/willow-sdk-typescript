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
- `registerSubgroveSignMessage`, `registerSubgroveUnsignedBincode`,
  `grantSubgroveKeySignMessage`, `rotateSubgroveKeySignMessage`,
  `unregisterStorageNodeSignMessage`, and `registerDidSignMessage`, which
  return the message (or, for a registration, the bincode its `Config`
  hashes) each of these transactions signs (see the README's "Registration,
  key grant, and storage-node signing").
- `WillowAuth.getAlgorithm()`, `getSignFunction()`, and
  `transactionSigner()`: the identity's algorithm, its sign function, and the
  identity as a transaction `Signer`.
- `RegisterSubgroveTx` carries every field of the chain's struct
  (`description`, `admins`, `checkpointVerification`, `privacy`,
  `initialOwnerKeyGrant`, `templateConfig`, `confirmationDepth`,
  `cryptographicCompleteness`), and the mode types are typed field by field
  (`ReadPricing`, `ExecutionMode`, `IndexerConfig`, `WasmModule`,
  `CompletenessCommitments`, `TemplateSubgroveConfig`, `TeeType`,
  `UintInput`).
- An optional `signFunction` argument to the `PrivacyOperations`
  constructor.
- `MerkExecutionResult.valueKeys`: the hex keys of every node in a merk
  proof that carries a value, whatever the limit.
- `NonceAllocator` (with `NONCE_WINDOW`, `NONCE_HOLD_MS`,
  `parseAccountNonceState`, `refusalKeepsNonce`, and the
  `AccountNonceState` and `NonceAllocatorOptions` types), which hands out
  an identity's transaction nonces; `ConsensusClient.nextNonce(did)` and
  `ConsensusClient.nonces`; a `nonceAllocator` option in `WillowConfig` and
  `ConsensusConfig`, and an optional last argument to the
  `PrivacyOperations` constructor.
- `serializeSchema(schema)`, which returns a data or file subgrove's schema
  as the JSON text the chain parses, `SCHEMA_FIELD_TYPES`, and the
  `SchemaFieldType` type. A `SchemaDefinition`'s field may be written as the
  chain's own type (`name: 'string'`) as well as a `FieldType`.
- `revokeSubgroveKeySignMessage`, which returns the message a
  RevokeSubgroveKey signs; `privacy.revokeSubgroveKey` uses it.
- `subgroveDataPath(subgroveId)`, the path a subgrove's data is proven at;
  the `PathSegment` type. `ProofVerificationOptions.path` takes segments as
  bytes too. An optional `options` argument to `verifyQueryResponse` and
  `subgroveId` argument to `extendQueryResponse`.
- `grovedb.verifyKeyAbsence(proofBytes, path, key)`, which verifies a proof
  that a key is absent at a path; the `ProvenEntry` type, its `tree` flag,
  and its `nodeType`, the merk node the proof gives the entry as.
- `TransactionSubmitError` (with the `SignedSubmission` type): a signed write
  that was sent and didn't go through, carrying its `did`, `nonce`, signed
  body (`transaction`), and, for a refusal at CheckTx, `result`.
  `ConsensusClient.resubmit(submission)` posts that body again under its
  nonce.
- An optional nonce source as the third argument to the `FileOperations`
  constructor (`WillowClient` passes its `ConsensusClient`), and the
  `FileNonceSource` and `FileSigningOptions` types.
- `verifyQuerySelection(subgroveId, query, response, options?)`, which
  verifies a `POST /query/:subgrove` response as the query's whole result;
  `QueryNotVerifiableError` (code `QUERY_NOT_VERIFIABLE`) for a query whose
  selection can't be reproduced, `QueryResultNotVerifiableError` (code
  `QUERY_RESULT_NOT_VERIFIABLE`, with `rootHash`) for data whose selection
  can't be reproduced, `DEFAULT_QUERY_LIMIT`, and the
  `QuerySelectionOptions` type.
- `grovedb.verifyCompleteLayer(proofBytes, path)`, which verifies a proof
  that reveals the whole subtree at a path and returns its every entry; the
  `CompleteEntry` and `CompleteLayer` types.
- `WillowData.getVerifiedData(subgrove, key)` and the `VerifiedData` type:
  a verified value with the root and block height it was verified against.
  `QueryResponse.verifiedHeight`.
- `lightClient.maxProofLagBlocks` (`WillowLightClientOptions`), default 20,
  and `LightClient.getLatestChainHeight()`, the highest height a majority of
  the endpoints that answer (and at least `minValidatorsForConsensus`) have
  reached.
- `BroadcastResult.pending`, `BroadcastResult.submission`, and
  `ConsensusClient.isNonceUsed(did, nonce)`.
- The `UNSUPPORTED` code of `VerifiableRpcError`.

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
- **Registrations, key grants, and storage-node removals sign every field
  and their nonce.** RegisterSubgrove is signed, in every mode, over its
  subgrove, owner, `Config` (the SHA-256 of the transaction's bincode with
  an empty signature), and nonce; GrantSubgroveKey and RotateSubgroveKey
  over every field of each grant; UnregisterStorageNode over the node and
  the nonce. The SDK sends every field of a registration explicitly and
  hashes exactly what it sends; u64 and u128 values above 2^53 − 1 are sent
  as exact digits. It refuses to sign a text field holding a `\n` or a lone
  surrogate, or a number outside its type.
- **`WillowClient` signs transactions with its identity's algorithm.** A
  secp256k1 identity's transactions were signed as Ed25519 and never
  verified. `PrivacyOperations` signs with its identity's algorithm too.
- A file manifest's `chunkCount` and `chunkSize` are u32 on the chain; a
  larger value is refused before signing or sending.
- **`ConsensusClient.transfer` sends and signs its amount as exact digits.**
  The amount (and `TransferTx.amount`) is a u128 and takes a `bigint` or a
  decimal string as well as a safe-integer number. An amount of 1000 WILL
  (10^21) or more, passed as a number, was sent and signed as `1e+21`,
  which the chain's u128 decoder refuses, so every such transfer failed
  (retried as a transport error while its nonce was held), and an amount
  above 2^53 could not be given exactly. A number that is not a safe
  integer, or a value outside u128, is refused (`INVALID_SIGNED_FIELD`)
  before a nonce is taken.
- **`WillowClient.registerDid` sends a RegisterDid transaction**, signed by
  the identity (the new DID), at nonce 1, and returns its
  `BroadcastResult`. The document goes as the chain's `DidDocument` and is
  signed over its JSON text as the chain writes it. The API has no DID
  registration route; `WillowAuth.registerDid` throws
  `UNSUPPORTED_OPERATION` naming this path.
- `createDidFromPublicKey` publishes an Ed25519 key as
  `Ed25519VerificationKey2018`, the type the chain derives a DID from and
  verifies.
- **`WillowData.registerSubgrove` sends a RegisterSubgrove transaction** and
  returns its `BroadcastResult`, as `WillowClient.registerSubgrove` does. The
  API has no REST registration route.
- `WillowData.storeData`, `batchStore`, `updateData`, and `deleteData`, and
  `WillowClient.update` and `delete`, throw `UNSUPPORTED_OPERATION` without
  sending anything. The API takes no data writes over REST (those routes
  answer 501), and the SDK builds no UpdateData or DeleteData transaction;
  a StoreData of an existing key is refused in its block. Write each new
  key with `client.store`.
- A registration's retention window goes into its BlockchainIndexing mode,
  in the chain's form; one for another mode is refused. It was sent as a
  top-level field the chain does not read.
- **Writes in flight together get distinct nonces.** Every write path that
  picks a nonce (`WillowClient`, `ConsensusClient`, `WillowData`, and
  `PrivacyOperations`) takes the lowest one in the chain's window
  (`base + 1 … base + 24`) that isn't used, seen to land, or handed out
  within the last 120 s; with a CometBFT RPC URL it reads which nonces in
  the window are used. A nonce refused at CheckTx is given back unless the
  refusal says it is held, used, or spent. A full window throws
  `NONCE_WINDOW_FULL`. Each write read the base and signed `base + 1`, so
  writes in flight together shared a nonce. Clients of one API URL in a
  process share the allocator.
- `ConsensusClient` without an `apiUrl` or an RPC URL refuses to pick a
  nonce (`API_URL_REQUIRED`); it used nonce 1.
- **A transaction is not signed with a guessed secp256k1.** An identity set
  without an algorithm whose key is `0x`-prefixed hex was guessed secp256k1,
  and its transactions signed so; an Ed25519 key can share that form.
  Transactions now throw `ALGORITHM_REQUIRED` until the algorithm is given
  to `setIdentity` or `init()`, or read by `init()` from the DID document;
  requests still sign with the guess. `init()` given no algorithm reads the
  key's type from the document with or without a key id; given a key id, it
  skipped the document and kept the guess. Given a key id, a lookup that
  fails in any way (a DID the API doesn't know, a network error, a 5xx, a
  400) still keeps the guess, and `init()` completes.
  `WillowAuth.transactionSigner(keyAlgorithm?)` takes the algorithm of the
  key the chain will verify with.
- `registerDid` (`WillowClient` and `ConsensusClient`) signs with the
  algorithm of the document's key: a guessed identity, or a signer without
  a `signFunction`, takes it, and an identity given another algorithm (or a
  signer whose `signFunction` is the SDK's other one) is refused
  (`ALGORITHM_MISMATCH`).
- `WillowData.registerSubgrove` and `WillowClient.registerSubgrove` throw
  `IDENTITY_MISMATCH` when the request's `owner_did` is not the identity;
  the identity was registered as owner regardless.
- `files.upload`, `files.delete`, and `files.unregisterStorageNode` take
  signing options as a required argument and throw `SIGNING_REQUIRED`
  without them, sending nothing. They sent an unsigned transaction, which
  the chain refuses.
- A DataStorage or FileStorage registration whose subgrove id is not 1–64
  ASCII letters, digits, `-`, or `_` starting with a letter or digit
  (`INVALID_SUBGROVE_ID`), or whose schema declares indexes
  (`SCHEMA_INDEXES_UNSUPPORTED`), is refused before it is signed or takes a
  nonce. The chain refuses both. The examples no longer declare indexes.
- A field marked `indexed: true` is refused (`SCHEMA_INDEXES_UNSUPPORTED`):
  the chain's schema has no per-field index. `FieldType.indexed` is
  deprecated.
- A data or file registration whose schema text the chain would not parse
  as its schema (not JSON, a field type it has no variant for, a `version`
  outside u32, a value of the wrong kind) is refused before it is signed
  (`INVALID_SCHEMA`). The chain refuses one in its block, which spends the
  nonce.
- A key grant, rotation, or revoke whose subgrove id is empty or holds a
  `:` (`INVALID_SUBGROVE_ID`), a grant or rotation to a grantee that is not
  a Willow DID, and a revoke whose revokee or sender is not one
  (`INVALID_DID`) are refused before they are signed, and by
  `PrivacyOperations` before a nonce is taken. The chain refuses each.
- A data or file registration whose admins, writers, or free readers are
  not Willow DIDs (`INVALID_DID`), and a private DataStorage registration
  whose initial key grant is not key epoch 0 granted to the owner
  (`INVALID_KEY_GRANT`), are refused before they are signed. The chain
  refuses each.
- Schema text is read as the chain's parser reads it: a `version` written as
  a float (`1.0`, `1e0`, `-0`), a schema key written twice, or a lone UTF-16
  surrogate escaped in a key, field name, field type, or required field is
  refused (`INVALID_SCHEMA`). `JSON.parse` takes each.
- `ConsensusClient` checks a write's fields before it reads or takes a
  nonce.
- A Transfer's `fromDid`, `toDid`, or `memo`, a DeregisterSubgrove's
  subgrove id or owner DID, and a SubmitAnchor's DID, anchor id, Merkle
  root, receipt hashes, timestamp, previous anchor hash, or anchor hash
  that is not a string or holds a lone UTF-16 surrogate is refused
  (`INVALID_SIGNED_FIELD`) before a nonce is taken, as every other signed
  text field is. A lone surrogate has no UTF-8 form, and the API refused the
  body.
- A StoreData whose data is not the JSON text of an object is refused before
  it is signed (`INVALID_SIGNED_FIELD`), and `client.store` and
  `consensus.storeData` refuse a value that is not a JSON object before
  taking a nonce. The chain refuses any other data in the block, which
  spends the nonce; `undefined` was signed as 0 bytes.
- **`ProofVerifier.verifyInclusionProof` and `verifyAbsenceProof` take the
  key's path (required)** and bind the key, the path, and the value (or the
  absence) to the proof. They returned true for any valid proof at the
  trusted root, and `verifyAbsenceProof` even when the key was present.
  `ProofVerifier.verifyQueryProof` binds each `queryResult` entry to an Item
  the proof proves; it ignored them.
- `FileSigningOptions.nonce` is optional: without it, `files.upload`,
  `files.delete`, and `files.unregisterStorageNode` take the lowest free
  nonce from their nonce source (`WillowClient.files` from
  `client.consensus`), and every file write settles its nonce with that
  allocator. A refused file write throws a `TransactionSubmitError`
  (`TX_SUBMIT_FAILED`), so its nonce is no longer lost with its result.
  Without a nonce or a nonce source a file write throws `NONCE_REQUIRED`.
- `TX_SUBMIT_FAILED` from `ConsensusClient` and `FileOperations`, and
  `BROADCAST_FAILED` from `PrivacyOperations`, are `TransactionSubmitError`s
  carrying the DID, nonce, and signed body.
- A repeat of a transaction the mempool already holds (CometBFT's "tx
  already exists in cache") returns `{ success: false, pending: true }`,
  without a `txHash`, and its nonce stays held. CometBFT caches a
  transaction before CheckTx runs and drops it if CheckTx refuses it, so
  the answer does not mean the transaction was accepted.
- A 4xx from `POST /tx/submit` (a body the API can't read, one too large, an
  API key it refuses, a rate limit) is a refusal: the request never reached
  CheckTx, so the write returns `{ success: false }` with `HTTP <status>`
  and the API's answer as its `errorMessage`, is not posted again, and gives
  its nonce back. It was a transport failure, which `ConsensusClient` posted
  again `maxRetries` times and then threw, and `FileOperations` and
  `PrivacyOperations` threw. A 4xx whose body says the transaction is
  already in the cache stays pending. The thrown error types are unchanged.
- A `ConsensusClient` write's result that is not `success` (pending, or
  refused at CheckTx) carries `submission` (its `did`, `nonce`, and signed
  body), and `client.store`, `client.registerDid`,
  `client.registerSubgrove`, and `client.data.registerSubgrove` throw it as
  a `TransactionSubmitError` (`TX_SUBMIT_FAILED`) with `result`, where they
  threw an `Error` with the message alone. `client.deregisterSubgrove`,
  which returned such a result without throwing, throws it too.
  `isNonceUsed` says whether a transaction with the nonce has been included
  in a block, not whether the write applied: a refusal in the block spends
  the nonce too.
- **`client.query` and `data.query` verify the query's whole result.** The
  proof must reveal every entry of the subgrove's data tree (no `Hash`,
  `KVHash`, or `KVDigest` node, and no subtree without its lower layer), and
  the SDK runs the API's selection over those entries (each item that parses
  as JSON, the one exact-match filter, the sort, `offset`, and `limit`,
  default 100, with numbers compared as their JSON text) and requires the
  response's `documents` and `total` to be exactly it, in order. They were
  only checked to be values the proof proves, so a proof revealing part of
  the tree, or a subset, duplicate, or filtered-out document, verified, and
  `total` and `offset` were not checked. A query whose selection the SDK
  can't reproduce throws `QUERY_NOT_VERIFIABLE` before anything is sent: a
  filter on more than one field (the API applies one), a filter operator (it
  applies none), or `search`. The proof's completeness and its root are
  checked before the selection is run, and data at the verified root whose
  selection can't be reproduced (a sort over values that are not all numbers
  or all strings, as on a field some selected document lacks or holds as
  `null`, a boolean, an array, or an object, or an object whose first key is
  `serde_json`'s private number or raw-value token) throws
  `QUERY_RESULT_NOT_VERIFIABLE`. The selection is the one in the body as
  sent. A number verifies, in queries and in `get`, when its text has the
  exact decimal value of the text JavaScript writes for the double it parses
  to (`String(Number(text))`), so every number JavaScript writes does, at
  any magnitude (`1e18` is `1000000000000000000`), and a document holding
  one whose text parses to a double JavaScript writes as another value
  (`9007199254740993`, read as 2^53, or `0.33333333333333331`) does not.
  The verified result carries `documents`, `total`, `offset`, `limit`,
  `proof`, `verifiedRootHash`, and `verifiedHeight`, and none of the API's
  other fields.
- **A verified read's proof height must be near the chain's.** `get`,
  `getData`, `getMultiple`, and `query` refuse a proof whose block height is
  more than `lightClient.maxProofLagBlocks` from the chain's latest height
  as the light client's endpoints report it (`PROOF_HEIGHT_OUT_OF_RANGE`),
  and one that names no height. The API chose the height with no bound.
- `getMultiple` leaves out a key the API reports absent only when the API's
  proof for it proves it absent at a verified root; otherwise it throws. It
  dropped such keys unchecked.
- `getMultiple` and `getMultipleUnverified` return an object with no
  prototype, each value an own property of its key. A key named
  `__proto__` set the result's prototype to the stored value, so a key
  proven absent read as that value's field of the same name. Test for a key
  with `key in result` or `Object.hasOwn(result, key)`: the result has no
  `hasOwnProperty` method.
- `get`, `getData`, `getVerifiedData`, and `getMultiple` refuse an answer
  that reports success but carries no value (`PROOF_VERIFICATION_FAILED`).
  Such an answer, with the key's genuine proof, was checked for the key
  alone: `get` returned `undefined`, and `getMultiple` reported the key
  absent without an absence proof.
- `get`, `getData`, `getMultiple`, `verifyItemProof` (and
  `GroveDBProofVerifier.verifyItemProof`) given a value, and
  `ProofVerifier.verifyInclusionProof` take a key's value only from the `KV`
  node holding an Item that grovedb proves a stored value in. A reference
  at the key (a `KVRefValueHash` node, whose value is the element it points
  to) was taken as the key's value; it, and an Item given as another node,
  is refused.
- **`queryHistoricalVerified` throws `UNSUPPORTED_OPERATION`** without
  sending anything, and is deprecated. It checked the proof against a state
  root from the same API that served the result, not from consensus, and
  the API returns no proof for a historical query. `queryHistorical` and
  `getCheckpointStateRoot` are documented as unverified.
- `LightClient.verifyQueryProof` checks a proof made at height H against the
  header of block H+1, which commits the state after H; it used header H.
- Proven Item bytes are read as UTF-8 strictly (a bad byte is not replaced,
  a byte-order mark is not dropped) before they are read as JSON, so other
  bytes can't bind as the same value.
- `VerifiableRpcOperations.verify` is documented as it is: `inclusion`
  means the GroveDB proof verifies to the response's own `state_root`, and
  neither `answer` nor the key is bound to the proof. `anchorStateRoot`,
  which it never implemented, throws `UNSUPPORTED`.
- `WillowClient.getRootHash()` is documented as the root the API reports,
  which the SDK does not verify.
- `sqlQuery`, `graphqlQuery`, `QuerySource`, and GraphQL subscriptions are
  documented as unverified: the SDK checks nothing on these paths, from a
  validator or an indexer, including a proof a response carries
  (`includeProof`). They were documented as consensus-verified, every row
  with Merkle proofs.
- `grovedb.deserializeElement` refuses trailing bytes.

### Removed

- `WillowAuth.getAuthParams()`. It built a `?did=` query parameter the server
  ignores.

### Fixed

- **A data or file subgrove's schema is sent in the chain's shape.** A
  `SchemaDefinition`'s fields went as objects (`{"name":{"type":"string"}}`),
  which the chain does not parse as its schema, so it refused, in its
  block, every registration that declared a field. `registerSubgrove` now
  sends
  `{"version":…,"fields":{"name":"string"},"indexes":[],"required_fields":[…]}`,
  each field as its type and each field marked `required` in
  `required_fields`.
- The GroveDB verifier refuses children under opaque proof nodes: a proof
  that attaches a child to a Hash node, whose hash would not cover it.
- The GroveDB verifier accepts a tree element proven without its lower layer
  (no subquery on it, an empty tree, an exhausted limit), as grovedb returns
  it. Its value hash is the layered one, so its bytes are not checked as a
  leaf value, and they bind no document or item value. A lower layer under a
  key its layer does not prove is refused.
- `verifyGroveDBProof` with `deserializeElements: false` verifies proofs
  with lower layers; it refused every one.
- **Query results are tied to the queried path.** `client.query` and
  `data.query` bind the documents to values proven at the subgrove's data
  path; with a path, a proof with a lower layer off it is refused. A proof could carry another
  subgrove's data, or a value at a prefix of the path, beside the queried
  data at the same root, and the documents bound to it. A proof that stops
  at a subtree on the path verifies as an empty result when it proves that
  subtree empty.
- A subtree proven without its lower layer is bound or not given: an empty
  one's value hash is re-derived from its bytes and checked; a non-empty
  one's result has `value` and `element` `null` (its bytes are not bound)
  and `tree: true`. An element must decode with no trailing bytes, so other
  bytes on an item's value hash no longer pass as a subtree.
- A nonce state read that advances the base keeps the used bits seen above
  it, so a base-only read can't hand out a nonce known to be used.
- Each send attempt renews a write's nonce hold, so another write can't take
  the nonce while the first is still being retried.

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
