# Willow TypeScript SDK

[![CI](https://github.com/willow-network/willow-sdk-typescript/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/willow-network/willow-sdk-typescript/actions/workflows/ci.yml)

TypeScript/JavaScript SDK for interacting with the Willow decentralized data infrastructure protocol. Provides cryptographic proof verification for all data operations using a pure TypeScript implementation of GroveDB verification.

## Features

- **Secure by Default**: All data operations automatically verify cryptographic proofs, and the returned documents are bound to the proof — a valid proof paired with unrelated data is rejected
- **Full Local Verification**: Pure TypeScript GroveDB proof verification — BLAKE3 hashing, Merk proof parser, bincode decoder, full layered verification. Runs in Node and the browser without WASM.
- **DID Authentication**: Ed25519 and secp256k1 (Ethereum-compatible) signature support
- **Light Client (experimental)**: CometBFT light-client scaffolding. The root-hash path currently trusts the configured RPC endpoint(s); header-signature verification is not wired in yet — see [Light Client](#light-client-experimental).
- **GKR Proof Verification**: Server-side verification via the `/verify-gkr-proof` endpoint. (A pure-Rust verifier exists and compiles to `wasm32`; binding it into this SDK is on the roadmap.)
- **File Storage**: Upload, download, list, and delete files with chunk Merkle verification (browser-safe; uses `Uint8Array` and `@noble/hashes`/`@noble/ciphers`)
- **File Encryption**: XChaCha20-Poly1305 encryption/decryption for private files
- **Collection Helpers**: Convenient API for working with a single subgrove
- **Silent by Default**: No console output unless you opt in via the injectable logger

> **Install from source.** Willow's SDKs are not yet published to package registries.
> The commands below install directly from this repository and work today.

## Installation

```bash
npm install github:willow-network/willow-sdk-typescript
# or
yarn add willow-network/willow-sdk-typescript
# or
pnpm add github:willow-network/willow-sdk-typescript
```

Requires Node.js >= 18 (the SDK uses the global `fetch`). In the browser it runs without polyfills.

## Transaction submission

Transactions submitted through this SDK go to the API server's
`POST /tx/submit` endpoint. The server accepts the JSON-encoded
transaction, bincode-encodes it (the chain's on-the-wire format), and
forwards to CometBFT's `broadcast_tx_sync`. `apiUrl` is therefore
**required** whenever you submit a tx; `consensusRpcUrl` is only used
for read-only RPC queries (status, block, validators). For localhost
devnets it is derived from `apiUrl` automatically; for any other host,
set it explicitly — operations that need CometBFT RPC throw with code
`CONSENSUS_RPC_URL_REQUIRED` when it is missing.

Token amounts are u128s in the token's smallest unit (1 WILL is 10^18), so
most are past 2^53 − 1, the largest integer a JavaScript number holds
exactly. `client.consensus.transfer` takes its amount as a `bigint` or a
decimal string (or a number that is a safe integer) and sends and signs its
exact digits:

```typescript
await client.consensus.transfer(fromDid, toDid, 1000n * 10n ** 18n, client.auth.transactionSigner());
```

## Quick Start

```typescript
import { WillowClient, generateWallet, createDidFromWallet } from '@willow-network/sdk';

// 1. Generate a wallet and DID
const wallet = generateWallet();
const didDocument = createDidFromWallet(wallet);

// 2. Initialize the client and set the identity. Transactions and signed
//    requests are signed with this key, by its algorithm.
const client = new WillowClient({ apiUrl: 'http://localhost:3031' });
client.auth.setIdentity(
  didDocument.id,
  wallet.privateKey,
  didDocument.publicKeys[0].id,
  'secp256k1',
);

// 3. Register the DID by a RegisterDid transaction, signed by its own key.
//    The DID must already hold the registration fee (see below).
await client.registerDid(didDocument);

// 4. Store data (requires the 'users' subgrove to exist — see below)
await client.store('users', 'alice', {
  name: 'Alice',
  score: 100,
});

// 5. Retrieve data (automatically verified!)
const data = await client.get('users', 'alice');
console.log(data);
```

> **Prerequisite:** `client.store()` writes into a *subgrove* that must already
> be registered on-chain and funded — step 4 fails otherwise. See
> [Register Subgrove](#register-subgrove) and `examples/app_registration.ts`
> for registering one, or use a devnet with pre-registered subgroves.
> Registration itself costs tokens, so the signing DID needs a funded balance.

A DID's id is derived from its key, so it can be funded before it is
registered: transfer at least the registration fee to `didDocument.id`, then
register it. For a DID already on chain, set `did` and `privateKey` in the
config and call `client.init()`, which reads the key id and algorithm from the
DID document.

## Configuration

`WillowConfig` options accepted by `new WillowClient({...})`:

| Option | Description |
|--------|-------------|
| `apiUrl` | **Required.** Willow API server URL (e.g. `http://localhost:3031`) |
| `consensusRpcUrl` | CometBFT RPC URL for consensus reads. Auto-derived only for localhost devnets; required otherwise (see [Transaction submission](#transaction-submission)) |
| `indexerUrl` | Pin queries to a specific indexer, skipping discovery. Required by `client.eth` and `client.verifiableRpc`, which only indexers serve |
| `did`, `privateKey` | Identity pre-seeded for `client.init()` |
| `apiKey` | Managed-tier API key (`wk_…`), sent as `X-API-Key` on every request |
| `proofVerificationOptions` | Per-client proof verification options, e.g. `{ expectedRootHash }` (see [Proof Verification API](#proof-verification-api)) |
| `logger` | SDK diagnostics sink. Defaults to `silentLogger` (no console output); pass `consoleLogger` or your own `WillowLogger` |
| `lightClient` | Overrides for the auto-created light client (`chainId`, `validatorEndpoints`, `minValidatorsForConsensus`, `maxProofLagBlocks`, …). The fallbacks are single-node devnet defaults |
| `webSocket` | WebSocket constructor for GraphQL subscriptions. Defaults to `globalThis.WebSocket` (browsers, Node >= 22); on older Node pass the `ws` package's `WebSocket` class |

```typescript
import { WillowClient, consoleLogger } from '@willow-network/sdk';
import WebSocket from 'ws'; // only needed on Node < 22 for subscriptions

const client = new WillowClient({
  apiUrl: 'https://api.willow.tech',
  consensusRpcUrl: 'https://your-node.example.com:26657',
  apiKey: 'wk_...',
  logger: consoleLogger,
  webSocket: WebSocket,
});
```

## Secure by Default: Automatic Proof Verification

`client.get` and `client.query` verify a proof of what they return and check the proof's root against the light client's root for the proof's block height:

- `get` returns a key's value only when the proof proves that value at the key in the subgrove's data.
- `query` returns a result only when it is the query's whole result: the proof reveals the subgrove's entire data tree, and the documents and `total` are exactly what the API's query selects from it, in its order (see [Query Data](#query-data)).
- The API chooses the block height it proves at, so a proof more than `lightClient.maxProofLagBlocks` blocks (default 20) from the chain's latest height is refused (`PROOF_HEIGHT_OUT_OF_RANGE`), as is a proof that names no height.
- The light client reads roots and the latest height from its configured endpoints and trusts them; the latest height is the one a majority of the endpoints that answer have reached (see [Light Client](#light-client-experimental)).

```typescript
// These operations automatically verify proofs:
const data = await client.get('dataset', 'key');
const results = await client.query('dataset', { filters: { status: 'active' } });

// Query results carry the root and block height they were verified against
console.log('Verified against root', results.verifiedRootHash, 'at height', results.verifiedHeight);

// For performance-critical scenarios, skip verification:
const unverifiedData = await client.getUnverified('dataset', 'key');
const unverifiedResults = await client.queryUnverified('dataset', { /* query */ });
```

## Data Operations

### Store Data

```typescript
// Store a new key: one StoreData transaction
await client.store('dataset-id', 'key', { field: 'value' });
```

Each key is written by its own transaction, sent through `POST /tx/submit`;
the API takes no data writes over REST (its data-write routes answer 501). Up to 24 writes from one identity
can be in flight together, each under its own nonce (see [Nonces](#nonces)).
Writes in flight may land in any order, so send a write that depends on
another (one to a subgrove being registered, say) after the first has landed:

```typescript
// At most 24 in flight: a 25th throws NONCE_WINDOW_FULL until earlier ones land.
await Promise.all(batch.map(({ key, value }) => client.store('dataset-id', key, value)));
```

### Retrieve Data

```typescript
// With automatic proof verification (secure by default)
const data = await client.get('dataset-id', 'key');

// Without verification (performance mode)
const data = await client.getUnverified('dataset-id', 'key');

// The value with the root and block height it was verified against
const { data, rootHash, height } = await client.data.getVerifiedData('dataset-id', 'key');

// Get multiple with verification
const collection = client.collection('dataset-id');
const multiple = await collection.getMultiple(['key1', 'key2', 'key3']);
```

`getMultiple` leaves out a key the API reports absent only when the API's
proof for the key proves it absent; otherwise it throws. An answer that
reports success but carries no value is refused (`PROOF_VERIFICATION_FAILED`):
there is nothing to check against the proof.

### Query Data

```typescript
// Query with automatic proof verification
const results = await client.query('dataset-id', {
  filters: { status: 'active' },
  sort: { field: 'score', order: 'desc' },
  limit: 10,
  offset: 0,
});

console.log('Documents:', results.documents);
console.log('Total:', results.total);
console.log('Verified root:', results.verifiedRootHash, 'at height', results.verifiedHeight);

// Query without verification
const results = await client.queryUnverified('dataset-id', {
  filters: { status: 'active' },
});
```

With a proof, the API proves the subgrove's whole data tree and selects from
every item in it: each item that parses as JSON, kept when its `filters`
field equals the given value (one field, matched exactly; a dotted name such
as `meta.kind` reaches into objects), sorted by the `sort` field (stably,
numbers by value and strings by code point), then `offset` and `limit`
(default 100) applied; `total` counts the documents selected before `offset`
and `limit`. `client.query` checks that the proof reveals the whole data
tree at the light client's root, then runs that selection over it and returns
the result only when the API's `documents` and `total` are exactly it. The
selection is the one in the body as sent, so changing the query object while
the request is in flight does not change what its result is checked against.
Numbers match as JSON text: `1` and `1.0` are different values. A document
holding a number JavaScript can't carry exactly (an integer beyond
2^53 − 1, or a decimal that `JSON.parse` rounds to a double JavaScript
writes as another value, such as `0.33333333333333331`) does not verify;
store such values as strings. Every number JavaScript writes verifies,
including results such as `1.1 * 1.1` (`1.2100000000000002`) and `1 / 3`.

A query the API does not apply as asked throws `QUERY_NOT_VERIFIABLE` before
anything is sent: a filter on more than one field (the API applies only one),
a filter operator such as `$gte` or `$in` (the API applies none), or
`search`. Read those with `queryUnverified`, or query on one exact field and
filter the verified documents further yourself. Data at the verified root
whose selection the SDK can't reproduce throws `QUERY_RESULT_NOT_VERIFIABLE`
(a `QueryResultNotVerifiableError` carrying `rootHash`): a sort over values
that are not all numbers or all strings, or a document holding an object
whose first key is `serde_json`'s private number or raw-value token, which
the API reads as something other than an object. The API's sort calls two
values equal unless both are numbers or both are strings, so when a selected
document lacks the sort field, or holds `null`, a boolean, an array, or an
object there, the API's order is not determined (unless the selected
documents hold at most one number and one string there), and every page of
that sorted query
throws, whatever its `offset` and `limit`: the order is checked over every
document the query selects. Sort on a field every selected document holds as
a number, or every one as a string: filter on a field that selects only such
documents, or read the result with `queryUnverified`.

### Update and Delete

Changing an existing key takes an UpdateData transaction, and deleting one a
DeleteData transaction. This SDK builds neither: a StoreData of an existing
key is refused, and `client.update`, `client.delete`, `data.updateData`, and
`data.deleteData` throw `UNSUPPORTED_OPERATION` without sending anything, as
do `data.storeData` and `batchStore`, which have no per-key transaction.

### Historical Data Queries

Query data at a checkpoint. The API routes a historical query to indexers who have declared availability for the checkpoint. The result is unverified: the checkpoint's state root and the data both come from the API, and the response carries no proof the SDK can check.

```typescript
// The state root the API reports for a checkpoint (not verified)
const checkpoint = await client.data.getCheckpointStateRoot(
  'uniswap-v3',
  'a1b2c3d4...'
);
console.log('State root:', checkpoint.state_root);
console.log('Block range:', checkpoint.block_range);

// Query historical data (unverified)
const result = await client.data.queryHistorical(
  'uniswap-v3',
  'a1b2c3d4...',
  {
    path: [[97, 112, 112, 115], [117, 115, 101, 114, 115]],
    key: [117, 115, 101, 114, 49, 50, 51],
  }
);

console.log('Provider:', result.provider_did);
console.log('Data:', result.data);
```

`queryHistoricalVerified` throws `UNSUPPORTED_OPERATION` without sending
anything: a proof checked against a state root from the same API that serves
the result shows nothing.

**Error Handling for Unavailable Data:**

```typescript
try {
  const result = await client.data.queryHistorical(...);
} catch (error) {
  if (error.can_reindex) {
    // No providers currently have this data
    // A new indexer can re-index the block range
    console.log('Data currently unavailable, can be re-indexed');
  }
}
```

## Collection Helper

For easier data management with a specific subgrove:

```typescript
const users = client.collection('users');

// All operations scoped to this collection
await users.store('alice', { name: 'Alice', score: 100 });
const alice = await users.get('alice');

// Query within collection
const topScorers = await users.query({
  filters: { team: 'red' },
  sort: { field: 'score', order: 'desc' },
  limit: 10,
});

// Unverified variants available
const fast = await users.getUnverified('alice');
const fastQuery = await users.queryUnverified({ /* ... */ });
```

## Root Hashes the API Reports

```typescript
// The root the API reports at /state/root-hash/verified (not verified by the SDK)
const reportedRoot = await client.getRootHash();

// The API node's local root (for debugging)
const localRoot = await client.getRootHashLocal();
```

Both are the API's answers, as trustworthy as the API. The verified reads
don't use them: `get` and `query` check each proof's root against the light
client's root for the proof's block height.

## Proof Verification API

What each function binds:

- `verifyQuerySelection(subgroveId, query, response)` verifies a
  `POST /query/:subgrove` result as the query's whole result (what
  `client.query` does): the proof must reveal the subgrove's entire data
  tree, and `response.documents` and `total` must be exactly what the API's
  query selects from it, in order. The proof's completeness and its root
  (`options.expectedRootHash`, when given) are checked before the selection
  is run. It throws `QUERY_NOT_VERIFIABLE` for a query whose selection it
  can't reproduce, and `QUERY_RESULT_NOT_VERIFIABLE` for data whose
  selection it can't reproduce, with the root of that data as `rootHash`
  (checked only against `expectedRootHash`).
- `verifyQueryProof`, `verifyQueryResponse`, and `GroveDBProofVerifier`
  check membership only: every document you pass in must deep-equal a value
  the proof commits to, so a server cannot pair a valid proof with unrelated
  data. They do not show that the documents are a query's whole result, or
  its result at all: a proof may leave entries out, and a subset, a
  duplicate, or a document a filter excludes passes.
- `verifyItemProof` binds one key's value at a path.

The computed root hash must still be compared against a trusted source to
establish that the proven state is canonical.

A proof of one subgrove's data can carry another subgrove's data at the same
root, so give the path the query was made at: `client.get` and `client.query`
do, and the functions below take it as `options.path`
(`subgroveDataPath(id)` is `["subgroves", id, "data"]`, where
`POST /query/:subgrove` and `GET /proof/:subgrove/:key` prove). With a path,
the proof must descend to it with no layer off it (or prove a subtree on it
empty, which is an empty result), and a document binds only to a value proven
at exactly that path. Without one, a document binds to a value proven
anywhere in the proof.

### Verification Options

There is no global configuration — options are passed explicitly, either
per-client or per-call:

```typescript
// Per-client: every automatic verification in get()/query() enforces the root
const client = new WillowClient({
  apiUrl: 'http://localhost:3031',
  proofVerificationOptions: { expectedRootHash: knownRootHash },
});

// Per-call: pass options as the last argument
const rootHash = await verifyQueryProof(proofHex, documents, {
  expectedRootHash: knownRootHash,
});
```

When `expectedRootHash` is set, verification throws unless the computed root
matches. For trustless operation, obtain the expected root from a trusted
source rather than hardcoding it.

### Manual Proof Verification

```typescript
import {
  verifyQuerySelection,
  verifyQueryProof,
  verifyItemProof,
  verifyQueryResponse,
  computeProofRootHash,
  subgroveDataPath,
  GroveDBProofVerifier,
} from '@willow-network/sdk';

// Verify a POST /query/:subgrove response as the query's whole result
const rootHash = await verifyQuerySelection('my-subgrove', query, response);

// Membership only: every document must be committed to by the proof, at the
// subgrove's data path
const rootHash = await verifyQueryProof(proofHex, documents, {
  path: subgroveDataPath('my-subgrove'),
});

// Verify a single item proof: enforces that the proof contains `key` at the
// given path AND that the proven payload deep-equals `value`
const rootHash = await verifyItemProof(proofHex, 'key', value, ['path', 'to', 'item']);

// Verify a QueryResponse object (membership of response.documents at the path)
const rootHash = await verifyQueryResponse(response, { path: subgroveDataPath('my-subgrove') });

// Fully verify a proof and return just the root hash (no document binding).
// Same cryptographic checks as verifyQueryProof.
const rootHash = await computeProofRootHash(proofHex);

// Structured results instead of throwing — options bound at construction
const verifier = new GroveDBProofVerifier({ expectedRootHash: expectedRoot });
const result = await verifier.verifyQueryProof(proofHex, documents);
// result: { valid: boolean, rootHash?: string, error?: string }
```

Deprecated (kept as aliases for one release): `extractRootHashFromProof`
(renamed to `computeProofRootHash`) and `verifyProofAdvanced` (use
`GroveDBProofVerifier`).

### Server-Assisted GKR Verification

GKR proofs are currently verified via the server endpoint. A pure-Rust
verifier (`willow-gkr-verify`) compiles cleanly to `wasm32` and is
the planned client-side path; until it's bundled into this SDK, browser
clients should call:

```typescript
const response = await fetch('http://localhost:3031/verify-gkr-proof', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    proof: proofHex,
    verification_key_hash: vkHashHex,
    public_inputs: {
      input_commitment: inputCommitmentHex,
      output_root: outputRootHex,
      block_range: [startBlock, endBlock],
      config_hash: configHashHex,
    },
  }),
});
const { data } = await response.json();
// data: { valid: boolean, error?: string }
```

GroveDB Merkle proof verification runs fully locally in Node and the
browser. GKR verification requires server trust until the wasm verifier
ships, and the root hash a proof is checked against currently comes from
the configured RPC endpoint (see [Light Client](#light-client-experimental)).

## GroveDB Verification Module

For low-level proof verification, import the `./grovedb` subpath (it is also
re-exported from the package root as the `grovedb` namespace):

```typescript
import * as grovedb from '@willow-network/sdk/grovedb';

// Full proof verification
const result = grovedb.verifyGroveDBProof(proofBytes, { expectedPath });
// result: { rootHash: Uint8Array, results: Array<{ path, key, value, element, tree }> }

// A proof that `key` is absent at `path` (throws unless it proves that)
const root = grovedb.verifyKeyAbsence(proofBytes, path, key);

// Verify against expected root (throws on mismatch)
const result = grovedb.verifyProofAgainstRoot(proofBytes, expectedRootHash);

// Quick verification (root hash only)
const rootHash = grovedb.quickVerify(proofBytes);

// Hash functions (BLAKE3-based)
const hash = grovedb.blake3Hash(data);
const vHash = grovedb.valueHash(value);
const kv = grovedb.kvHash(key, value);
const node = grovedb.nodeHash(kvHash, leftHash, rightHash);
const combined = grovedb.combineHash(a, b);

// Utility functions
const hex = grovedb.bytesToHex(bytes);
const bytes = grovedb.hexToBytes(hex);
const equal = grovedb.hashEquals(hash1, hash2);
```

Each result's `value` is the element bytes the proof binds to its key. An
entry with `tree: true` is a subtree, not a value: an empty one comes with its
bytes, which the proof binds; a non-empty one proven without its lower layer
has a value hash its bytes alone can't re-derive, so it comes with `value` and
`element` `null` and proves only that its key is present. An element must
decode with no trailing bytes.

With `expectedPath`, the proof must carry a layer for each segment and no
layer off the path, or stop at a subtree on the path that it proves empty.
`verifyKeyAbsence` requires that, and that the merk proof at `path` shows
where `key` would be with nothing unrevealed there.

The light client's `ProofVerifier` checks a key at its path against a trusted
root: `verifyInclusionProof(key, value, proofBytes, trustedRoot, path)` is
true only when the proof proves the Item `value` at `key` under `path`, and
`verifyAbsenceProof(key, proofBytes, trustedRoot, path)` only when it proves
`key` absent there. Both require the path.

## Light Client (Experimental)

> **Current trust model — read before relying on this.** The root-hash path
> (`getVerifiedRootHash` / `getVerifiedRootHashAtHeight`) reads `app_hash`
> directly from the configured RPC endpoint(s) and trusts the response;
> header-signature verification of the fetched root is not yet wired into
> that path. Separately, `verifyHeader` cannot yet validate real CometBFT
> commit signatures (sign-bytes encoding mismatch — CometBFT signs protobuf
> `CanonicalVote`), so header verification is experimental. Until both land,
> the trust assumption is "the configured RPC endpoints are honest", not
> "2/3+ of validator voting power signed this state".

```typescript
import { LightClient, LightClientConfigBuilder } from '@willow-network/sdk';

// Configure light client (chainId is a required constructor arg)
const config = new LightClientConfigBuilder('willow-chain')
  .validatorEndpoints([
    'http://validator1:26657',
    'http://validator2:26657',
    'http://validator3:26657',
  ])
  .trustThreshold(2, 3)
  .maxClockDriftSecs(10)
  .minValidatorsForConsensus(2)
  .autoSync(true)
  .build();

// Create and start light client
const lightClient = new LightClient(config);
await lightClient.start();

// Sync to latest
await lightClient.syncToLatest();

// Verify a query proof made at height H against the header of H+1, which
// commits the state after H (membership of proof.queryResult only)
const result = await lightClient.verifyQueryProof(proof);

// The chain's latest height, as a majority of the endpoints report it
const latest = await lightClient.getLatestChainHeight();

// Get verified headers
const latestHeader = await lightClient.getLatestHeader();
const headerAtHeight = await lightClient.getHeaderByHeight(1000);

// Export/import state for persistence
const state = await lightClient.exportTrustedState();
// ... save to disk ...
await lightClient.importTrustedState(savedState);

// Cleanup
await lightClient.stop();
```

## DID Authentication

### Ed25519 (Default)

```typescript
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from '@willow-network/sdk';

// Generate key pair
const { privateKey, publicKey } = generateEd25519KeyPair();

// Sign a message
const signature = signEd25519('Hello, Willow!', privateKey);

// Verify signature
const isValid = verifyEd25519('Hello, Willow!', signature, publicKey);
```

### Secp256k1 (Ethereum-compatible)

```typescript
import { generateWallet, createDidFromWallet } from '@willow-network/sdk';

// Generate Ethereum-compatible wallet
const wallet = generateWallet();
const didDocument = createDidFromWallet(wallet);

// Use with client: the algorithm is not in the DID, so name it
const client = new WillowClient({ apiUrl: 'http://localhost:3031' });
client.auth.setIdentity(
  didDocument.id,
  wallet.privateKey, // 0x-prefixed Ethereum private key
  didDocument.publicKeys[0].id,
  'secp256k1',
);
```

The client signs its transactions and signed requests with the identity's
algorithm: `client.auth.transactionSigner()` gives the key, key id, and sign
function (`signSecp256k1` or `signEd25519`) a transaction is signed with.
`client.init()` reads the algorithm from the on-chain DID document's key type.
Without either, the algorithm is guessed from the key's format, and an
Ed25519 key can share the `0x`-prefixed form: the client signs requests with
the guess but refuses to sign a transaction with a guessed secp256k1
(`ALGORITHM_REQUIRED`). `registerDid` signs with the algorithm of the
document's key, and refuses an identity given another (`ALGORITHM_MISMATCH`).

`createDidFromWallet` and `createDidFromPublicKey` publish a secp256k1 key in its 33-byte compressed form. `signSecp256k1(message, privateKey)` and `verifySecp256k1(message, signature, publicKey)` sign and verify as the chain does: ECDSA over the Keccak-256 of the message, lower-S. `signSecp256k1` returns `0x`-prefixed hex. `verifySecp256k1` decodes a signature as the chain does, reading an unprefixed one as base64 first, so it refuses an unprefixed hex signature the chain would refuse.

### Request signing

With an identity set, the client signs each read of subgrove data it sends to the API (`GET /data/:subgrove/:key`, `GET /proof/:subgrove/:key`, and `POST /query/:subgrove`, `/sql/:subgrove`, and `/graphql/:subgrove`) with a one-time nonce over the whole request. Only this form carries the DID's read rights: a Reader permission on a subgrove, or a place on a priced subgrove's free-reader list.

The headers are `X-DID`, `X-Public-Key-ID`, `X-Signature`, `X-Timestamp`, and `X-Nonce`. The signature is over eight lines:

```
willow-request-v2
<DID>
<public key id>
<METHOD>
<path and query, exactly as sent>
<Unix timestamp>
<nonce>
<hex SHA-256 of the body>
```

- The path and query are those of the URL as sent, percent-encoded, less any path the `apiUrl` carries.
- The server accepts a timestamp up to 300 s old and 30 s ahead, and each (DID, nonce) once. The client signs each request with a new nonce.
- A nonce is 16 to 128 characters of `A-Z a-z 0-9 - _`. `newRequestNonce()` makes one of 32 hex characters.
- Ed25519 signatures are sent as hex. secp256k1 signatures are over the Keccak-256 of the message and are sent as `0x`-prefixed hex.
- Requests sent to an indexer are not signed this way.

The client's other signed requests (key-grant reads and transaction submission) use the older form described below.

To sign a read you send yourself:

```typescript
const headers = client.auth.signRequestWithNonce('POST', '/query/my-subgrove', body);
```

`client.auth.signRequest(method, path)` makes the older `{METHOD}:{PATH}:{TIMESTAMP}` form, over the path without its query string. It proves the DID but carries none of its read rights, and it can be replayed with any body until the timestamp expires.

### Data and file write signing

A data write (`client.store`, `consensus.storeData`), a file manifest (`files.upload`, `consensus.storeFileManifest`), and a file delete (`files.delete`, `consensus.deleteFileManifest`) are transactions signed over labelled lines that bind the nonce and every field the transaction writes. The message is UTF-8, its lines joined by `\n` (the byte 0x0A) with no trailing newline:

```
StoreData
Subgrove: <subgrove id>
Key: <key>
Owner: <owner DID>
DataHash: <hex SHA-256 of the data bytes sent>
Nonce: <nonce>
```

```
StoreFileManifest
Subgrove: <subgrove id>
Key: <file key>
Owner: <owner DID>
Filename: <filename>
ContentType: <content type>
TotalSize: <total size>
ContentHash: <hex of the 32-byte content hash>
ChunkCount: <chunk count>
ChunkSize: <chunk size>
ChunkMerkleRoot: <hex of the 32-byte chunk Merkle root>
Encryption: none
Nonce: <nonce>
```

```
DeleteFileManifest
Subgrove: <subgrove id>
Key: <file key>
Owner: <owner DID>
Nonce: <nonce>
```

- Text fields go in verbatim, with no escaping or normalization; non-ASCII text is its UTF-8 bytes.
- The data bytes are the UTF-8 of the JSON text the transaction carries (`JSON.stringify(value)` for `storeData`).
- Numbers are unsigned decimal. The chain's nonces and sizes are u64 and its chunk count and chunk size u32, and a JavaScript number is exact only up to 2^53 − 1 (`Number.MAX_SAFE_INTEGER`), so the SDK refuses a value outside its type, or a negative or fractional one, rather than round it.
- Hex is lowercase without `0x`.
- The nonce is the one the transaction carries, so the message is built after the nonce is chosen. A write the chain refuses in its block after its signature and nonce verify (data not found, no permission, fee not collected, …) still spends the nonce; to retry, sign again under the next free nonce. A transaction refused for its signature or nonce spends nothing.
- The SDK refuses to sign when the subgrove id, key, owner DID, filename, or content type holds a `\n` (0x0A). A CR or U+2028 holds no 0x0A and is signed as it is.

`storeDataSignMessage(tx)`, `storeFileManifestSignMessage(tx)`, and `deleteFileManifestSignMessage(tx)` return the exact message for a transaction.

### Registration, key grant, and storage-node signing

A subgrove registration (`client.registerSubgrove`, `consensus.registerSubgrove`), a key grant or rotation (`privacy.grantSubgroveKey`, `privacy.rotateSubgroveKey`), and a storage node's removal (`files.unregisterStorageNode`) are signed the same way, over labelled lines that bind the nonce and every field:

```
RegisterSubgrove
Subgrove: <subgrove id>
Owner: <owner DID>
Config: <hex SHA-256 of the transaction's bincode with an empty signature>
Nonce: <nonce>
```

```
GrantSubgroveKey
Subgrove: <subgrove id>
Sender: <sender DID>
Grantee: <grantee DID>
GranteeKey: <grantee public key id>
KeyEpoch: <key epoch>
EphemeralKey: <hex of the ephemeral public key>
EncryptedKey: <hex of the encrypted key>
GrantedBy: <granting DID>
GrantedAt: <Unix seconds>
Nonce: <nonce>
```

```
RotateSubgroveKey
Subgrove: <subgrove id>
Sender: <sender DID>
NewEpoch: <new epoch>
Grants: <number of grants>
<for each grant, in order, its seven lines from Grantee to GrantedAt>
Nonce: <nonce>
```

```
UnregisterStorageNode
Node: <node DID>
Nonce: <nonce>
```

- `Config` hashes the registration's bincode (bincode 1.x: fixed-width little-endian integers, u64 lengths, a one-byte option tag, a u32 enum variant index) with an empty signature, so every field is signed, in every mode. The SDK sends every field of the chain's `RegisterSubgroveTx` explicitly, the chain's default for one the caller left out written out, and hashes exactly the values the chain decodes from that JSON. `registerSubgroveUnsignedBincode(tx)` returns those bytes.
- u64 and u128 values (funding, read prices, indexer stakes and rewards) are never rounded: pass a value above 2^53 − 1 as a `bigint` or a decimal string. The SDK sends it as its exact digits.
- A retention window belongs to a BlockchainIndexing mode; the SDK refuses one for another mode.
- The SDK refuses to sign when a subgrove id, owner, sender, grantee, key id, granting DID, or node DID holds a `\n` (0x0A), when a text field holds a lone UTF-16 surrogate (it has no UTF-8 form), or when a number is outside its type.
- RevokeSubgroveKey (`privacy.revokeSubgroveKey`) is signed over `RevokeSubgroveKey:<subgrove id>:<revokee DID>:<sender DID>:<nonce>`, which binds every field. `revokeSubgroveKeySignMessage(tx)` returns it.
- The chain refuses a key grant, rotation, or revoke whose subgrove id is empty or holds a `:` (`INVALID_SUBGROVE_ID`), a grant or rotation whose grantee is not a Willow DID, and a revoke whose revokee or sender is not one (`INVALID_DID`). A Willow DID is `did:willow:` followed by one or more ASCII letters, digits, `_`, or `-`, at most 128 bytes in all. The SDK refuses these before signing, and `PrivacyOperations` before taking a nonce.
- A DID registration (`client.registerDid`, `consensus.registerDid`) is signed over the JSON text of the DID document as the chain's `DidDocument` writes it (its fields in order, absent options as `null`), at nonce 1. `registerDidSignMessage(tx)` returns it.

`registerSubgroveSignMessage(tx)`, `grantSubgroveKeySignMessage(tx)`, `rotateSubgroveKeySignMessage(tx)`, `revokeSubgroveKeySignMessage(tx)`, and `unregisterStorageNodeSignMessage(tx)` return the exact message for a transaction.

### Nonces

The chain accepts a nonce in `base + 1 … base + 24` that it hasn't used, and its base advances only over used nonces with no gap. Every write path that picks a nonce (`WillowClient`, `ConsensusClient`, `WillowData`, and `PrivacyOperations`) takes it from a `NonceAllocator`, which keeps, per DID, the nonces it has handed out that haven't landed and the newest nonce state the chain has reported:

- It reads the account's base (`/account/{did}/nonce` on the API) or, with a CometBFT RPC URL, the base and which of the 24 nonces above it are used (ABCI query `/store/account_nonce_state/{did}`), and hands out the lowest nonce in the window that isn't used, seen to land, or handed out within the last 120 s. Writes in flight together get distinct nonces.
- When every nonce in the window is taken it throws `NONCE_WINDOW_FULL`; it never takes one above `base + 24`. A batch of more than 24 writes from one identity sends the rest once earlier ones land.
- A write refused at CheckTx gives its nonce back, unless the refusal says the nonce is held by a pending transaction, already used, or spent. A write accepted at CheckTx holds its nonce, and one whose submission failed in transport keeps it, until it lands or 120 s pass; a nonce handed out 120 s ago that hasn't landed is free again.
- Every client of one API URL in the process shares one allocator (`NonceAllocator.shared(apiUrl)`) unless given its own (`nonceAllocator` in `WillowConfig` or `ConsensusConfig`, or `PrivacyOperations`' last argument).
- `files.upload`, `files.delete`, and `files.unregisterStorageNode` take signing options (the chain refuses an unsigned transaction, so without them they throw `SIGNING_REQUIRED`). Leave `signing.nonce` out and the write takes its nonce from `client.consensus`, as every other write does; or pass one taken with `client.consensus.nextNonce(did)`. Either way the outcome is settled with the allocator: an accepted write holds its nonce, a refused one gives it back unless the refusal says it is held, used, or spent. A `FileOperations` made without a nonce source needs `signing.nonce` (`NONCE_REQUIRED`).
- Each send attempt renews the nonce's hold, so no other write takes it while the write is in flight, however long its retries run.
- A write that was sent and didn't go through throws a `TransactionSubmitError` (`TX_SUBMIT_FAILED`, or `BROADCAST_FAILED` from `PrivacyOperations`) carrying `did`, `nonce`, the signed body (`transaction`), and, for a refusal at CheckTx, the chain's answer (`result`). To retry a write that never landed under its own nonce, post the same signed body again with `client.consensus.resubmit(error)`: whichever attempt lands first spends the nonce. A repeat of a transaction the mempool already holds (CometBFT's "tx already exists in cache") returns `{ success: false, pending: true }` without a `txHash`: CometBFT caches a transaction before CheckTx runs and drops it if CheckTx refuses it, so the outcome is unknown. Its nonce stays held.
- A `ConsensusClient` result that is not `success` (pending, or refused at CheckTx) carries `submission`: its `did`, `nonce`, and signed body. `client.store`, `client.registerDid`, `client.registerSubgrove`, and `client.data.registerSubgrove` throw such a result as a `TransactionSubmitError` (`TX_SUBMIT_FAILED`) with the same fields and `result`. `client.consensus.isNonceUsed(did, nonce)` says whether a transaction with the nonce has been included in a block, not whether the write applied: a transaction refused in its block spends its nonce too, so read the state the write changes to confirm it. While the nonce is unused, `client.consensus.resubmit(error)` posts the same signed body again.

## Registration

### Register Subgrove

A *subgrove* is Willow's on-chain unit of storage — a named subtree with a
schema and access lists. Data operations target a subgrove by id, and writes
fail until the subgrove is registered (and its registration fee paid by a
funded DID). A subgrove is registered by a RegisterSubgrove transaction
signed by its owner, the client's identity; `client.registerSubgrove` and
`client.data.registerSubgrove` both send one. `registerDataset` is a
deprecated alias of `registerSubgrove`; "subgrove" is the on-chain term.

```typescript
// Returns the consensus BroadcastResult (txHash, height, rawLog)
const result = await client.registerSubgrove({
  dataset_id: 'users',
  name: 'User Data',
  schema: {
    version: 1,
    fields: {
      name: 'string',
      score: 'number',
      active: 'boolean',
    },
    required_fields: ['name'],
  },
  owner_did: didDocument.id,
  writers: [didDocument.id],
  readers: [],
});
```

A data or file subgrove's schema goes on chain as JSON text, which the chain
parses as its schema: a `version` (u32, default 1), `fields` mapping each
field name to one of `string`, `number`, `boolean`, `array`, `object`, or
`bytes` (default `{}`), `indexes` (default `[]`), and `required_fields`
(default `[]`). The SDK sends a `SchemaDefinition` in exactly that shape
(`serializeSchema(schema)` returns the text):

```json
{"version":1,"fields":{"active":"boolean","name":"string","score":"number"},"indexes":[],"required_fields":["name"]}
```

A field's type can also be written as an object, `{ type: 'string' }`; it is
sent as its `type`, and `required: true` adds the field to
`required_fields`. A type the chain has none of is refused with
`INVALID_SCHEMA`, as is schema text given to `consensus.registerSubgrove`
that the chain would not parse (the chain refuses such a registration in its
block, which spends the nonce). The text is read as the chain's parser reads
it, which is stricter than `JSON.parse`: `version` must be written as an
integer (`1`, not `1.0`, `1e0`, or `-0`), none of `version`, `fields`,
`indexes`, and `required_fields` may appear twice, and no key, field name,
field type, or required field may hold a lone UTF-16 surrogate (a `\u`
escape of one). Any other key, and its value, is ignored.

The chain also refuses a DataStorage or FileStorage registration whose
subgrove id is not 1–64 ASCII letters, digits, `-`, or `_` starting with a
letter or digit, whose admins, writers, or free readers are not Willow DIDs
(`did:willow:` followed by one or more ASCII letters, digits, `_`, or `-`, at
most 128 bytes), or whose schema declares indexes; and a private DataStorage
registration whose initial key grant is not key epoch 0 granted to the owner.
The SDK refuses each, with `INVALID_SUBGROVE_ID`, `INVALID_DID`,
`SCHEMA_INDEXES_UNSUPPORTED`, or `INVALID_KEY_GRANT`; leave `indexes` out or
empty. The chain's schema has no per-field index, so a field marked
`indexed: true` is refused as well. Each of these refusals comes before the
registration is signed or its nonce is read.

## Error Handling

```typescript
import { WillowError } from '@willow-network/sdk';

try {
  await client.get('dataset-id', 'key');
} catch (error) {
  if (error instanceof WillowError) {
    switch (error.code) {
      case 'DATA_NOT_FOUND':
        console.log('Key does not exist');
        break;
      case 'PROOF_VERIFICATION_FAILED':
        console.error('Data may have been tampered with!');
        break;
      case 'AUTH_FAILED':
        console.log('Authentication required');
        break;
      default:
        console.error(`Error: ${error.message} (${error.code})`);
    }
  }
}
```

A write whose submission failed after it was sent throws a
`TransactionSubmitError` with the DID, nonce, and signed body it used. It may
yet land, so retry it under the same nonce by posting the same body:

```typescript
import { TransactionSubmitError } from '@willow-network/sdk';

try {
  await client.store('dataset-id', 'key', { a: 1 });
} catch (error) {
  if (error instanceof TransactionSubmitError && !error.result) {
    await client.consensus.resubmit(error);
  }
}
```

## API Reference

### WillowClient

| Method | Description |
|--------|-------------|
| `init()` | Initialize with authentication |
| `registerDid(didDocument)` | Register the identity's DID by a RegisterDid transaction (returns the consensus `BroadcastResult`) |
| `registerSubgrove(request)` | Register a subgrove (returns the consensus `BroadcastResult`) |
| `deregisterSubgrove(subgroveId)` | Deregister a subgrove; remaining funding refunds to the owner |
| `store(datasetId, key, value)` | Store a new key by a StoreData transaction |
| `get(datasetId, key)` | Get data with proof verification |
| `data.getVerifiedData(datasetId, key)` | Get data with proof verification, with the root and block height it was verified against |
| `getUnverified(datasetId, key)` | Get data without verification |
| `update(datasetId, key, value)` | Throws `UNSUPPORTED_OPERATION` (see [Update and Delete](#update-and-delete)) |
| `delete(datasetId, key)` | Throws `UNSUPPORTED_OPERATION` |
| `query(datasetId, query)` | Query, verified as the query's whole result (`QUERY_NOT_VERIFIABLE` or `QUERY_RESULT_NOT_VERIFIABLE` when it can't be) |
| `queryUnverified(datasetId, query)` | Query without verification |
| `sqlQuery(subgroveId, sql, options?)` | SQL query routed to indexer or validator |
| `graphqlQuery(subgroveId, query, options?)` | GraphQL query routed to indexer or validator |
| `getProof(datasetId, key)` | Get raw Merkle proof |
| `getRootHash()` | The root the API reports at `/state/root-hash/verified` (not verified by the SDK) |
| `getRootHashLocal()` | The API node's local root hash |
| `collection(datasetId)` | Create collection helper |
| `auth.setIdentity(did, privateKey, publicKeyId, algorithm?)` | Set the identity that signs transactions and requests |
| `auth.transactionSigner()` | The identity as a transaction signer, with its algorithm's sign function |
| `auth.hasIdentity()` | Check whether an identity is set |
| `auth.signRequestWithNonce(method, pathAndQuery, body?)` | Nonce-form signature headers for a request (see [Request signing](#request-signing)) |
| `auth.signRequest(method, path)` | Older-form signature headers |

### Data Client Historical Methods

| Method | Description |
|--------|-------------|
| `data.getCheckpointStateRoot(subgroveId, checkpointId)` | The state root the API reports for a checkpoint (not verified) |
| `data.queryHistorical(subgroveId, checkpointId, query)` | Query historical checkpoint data (unverified) |
| `data.queryHistoricalVerified(subgroveId, checkpointId, query)` | **Deprecated**: throws `UNSUPPORTED_OPERATION` |

### Proof Verification Functions

| Function | Description |
|----------|-------------|
| `verifyQuerySelection(subgroveId, query, response, options?)` | Verify a query response as the query's whole result, returns root hash |
| `verifyQueryProof(proofHex, documents, options?)` | Verify query proof and check each document is a value it proves (at `options.path`; membership only), returns root hash |
| `verifyItemProof(proofHex, key, value, path, options?)` | Verify item proof and bind key/value/path to it, returns root hash |
| `verifyQueryResponse(response, options?)` | Verify QueryResponse object, checking membership of its documents (at `options.path`) |
| `subgroveDataPath(subgroveId)` | The path a subgrove's data is proven at, `["subgroves", subgroveId, "data"]` |
| `computeProofRootHash(proofHex)` | Fully verify proof and return root hash (no document binding) |
| `new GroveDBProofVerifier(options?)` | Stateful verifier returning `{ valid, rootHash?, error? }` instead of throwing |
| `extractRootHashFromProof(proofHex)` | **Deprecated** alias of `computeProofRootHash` |
| `verifyProofAdvanced(proofHex, documents, options?)` | **Deprecated** — use `GroveDBProofVerifier` |

### Utilities

| Function | Description |
|----------|-------------|
| `generateWallet()` | Generate Ethereum wallet |
| `createDidFromWallet(wallet)` | Create DID from wallet |
| `generateEd25519KeyPair()` | Generate Ed25519 key pair |
| `signEd25519(message, privateKey)` | Sign with Ed25519 |
| `verifyEd25519(message, signature, publicKey)` | Verify Ed25519 signature |
| `signSecp256k1(message, privateKey)` | Sign with secp256k1 over Keccak-256 (`0x`-prefixed compact signature) |
| `verifySecp256k1(message, signature, publicKey)` | Verify a secp256k1 signature |
| `signedRequestMessage(did, keyId, method, pathAndQuery, timestamp, nonce, body?)` | The eight-line message a nonce-signed request signs |
| `legacyRequestMessage(method, path, timestamp)` | The older-form message |
| `newRequestNonce()` | A fresh request nonce |
| `storeDataSignMessage(tx)` | The message a data write signs (see [Data and file write signing](#data-and-file-write-signing)) |
| `storeFileManifestSignMessage(tx)` | The message a file manifest signs |
| `deleteFileManifestSignMessage(tx)` | The message a file delete signs |
| `registerSubgroveSignMessage(tx)` | The message a subgrove registration signs (see [Registration, key grant, and storage-node signing](#registration-key-grant-and-storage-node-signing)) |
| `registerSubgroveUnsignedBincode(tx)` | The bincode a registration's `Config` hashes |
| `grantSubgroveKeySignMessage(tx)` | The message a key grant signs |
| `rotateSubgroveKeySignMessage(tx)` | The message a key rotation signs |
| `revokeSubgroveKeySignMessage(tx)` | The message a key revoke signs |
| `unregisterStorageNodeSignMessage(tx)` | The message a storage node's removal signs |
| `registerDidSignMessage(tx)` | The message a DID registration signs |
| `serializeSchema(schema)` | A data or file subgrove's schema as the JSON text the chain parses (see [Register Subgrove](#register-subgrove)) |
| `isValidDid(did)` | Validate DID format |

## Security Model

The SDK provides two levels of security:

1. **Full Local Verification** (default)
   - Pure TypeScript GroveDB proof verification
   - BLAKE3 hashing, Merk proof execution
   - Binds a key's value to the proof; verifies a query's result as its
     whole result
   - Compares against the root for the proof's block height, which must be
     near the chain's latest, both read from the configured RPC endpoints
     (see [Light Client](#light-client-experimental) for the exact trust
     assumption)

2. **Unverified** (opt-in via `*Unverified` methods)
   - Trusts the node completely
   - Maximum performance
   - Use only with trusted nodes

## Known Issues

- **Transitive `ws` advisory (moderate, not reachable from SDK code).** `ethers`
  pins `ws@8.17.1` exactly (every published `ethers` 6.x does, including the
  latest), and that `ws` carries moderate advisory
  [GHSA-58qx-3vcg-4xpx](https://github.com/advisories/GHSA-58qx-3vcg-4xpx)
  (uninitialized memory disclosure on the WebSocket *server*). A fresh install
  of this package therefore reports one moderate finding under `npm audit`.
  The SDK does not use `ethers`' WebSocket provider or run a `ws` server, so
  the advisory is not reachable from any SDK code path. There is no `ethers`
  release that pins a patched `ws`, so it cannot be resolved by bumping the
  dependency; consumers who want a clean audit can pin a newer `ws` via their
  own `overrides`/`resolutions` (the SDK's own `overrides.ws` only applies when
  the SDK is the root project, not when it is installed as a dependency).

## License

MIT
