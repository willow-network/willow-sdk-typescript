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

## Installation

> **Not yet published to npm.** Until the first release lands, install from git:
> `npm install github:willow-network/willow-sdk-typescript`

```bash
npm install @willow-network/sdk
# or
yarn add @willow-network/sdk
# or
pnpm add @willow-network/sdk
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

## Quick Start

```typescript
import { WillowClient, generateWallet, createDidFromWallet } from '@willow-network/sdk';

// 1. Generate a wallet and DID
const wallet = generateWallet();
const didDocument = createDidFromWallet(wallet);

// 2. Initialize the client (pre-seed config.did + privateKey so client.init()
//    can fetch the key id from the DID document).
const client = new WillowClient({
  apiUrl: 'http://localhost:3031',
  did: didDocument.id,
  privateKey: wallet.privateKey,
});

// 3. Register and bootstrap the identity for per-request signing
await client.registerDid(didDocument);
await client.init();

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

For ad-hoc identity (no `config.did` baked in) just call
`client.auth.setIdentity(did, privateKey, publicKeyId)` directly.

## Configuration

`WillowConfig` options accepted by `new WillowClient({...})`:

| Option | Description |
|--------|-------------|
| `apiUrl` | **Required.** Willow API server URL (e.g. `http://localhost:3031`) |
| `consensusRpcUrl` | CometBFT RPC URL for consensus reads. Auto-derived only for localhost devnets; required otherwise (see [Transaction submission](#transaction-submission)) |
| `indexerUrl` | Pin queries to a specific indexer, skipping discovery |
| `did`, `privateKey` | Identity pre-seeded for `client.init()` |
| `apiKey` | Managed-tier API key (`wk_…`), sent as `X-API-Key` on every request |
| `proofVerificationOptions` | Per-client proof verification options, e.g. `{ expectedRootHash }` (see [Proof Verification API](#proof-verification-api)) |
| `logger` | SDK diagnostics sink. Defaults to `silentLogger` (no console output); pass `consoleLogger` or your own `WillowLogger` |
| `lightClient` | Overrides for the auto-created light client (`chainId`, `validatorEndpoints`, `minValidatorsForConsensus`, …). The fallbacks are single-node devnet defaults |
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

All data operations automatically verify cryptographic proofs against the consensus-verified root hash, and the documents returned to you are bound to the proof — a response pairing a valid proof with data the proof does not commit to is rejected:

```typescript
// These operations automatically verify proofs:
const data = await client.get('dataset', 'key');
const results = await client.query('dataset', { filters: { status: 'active' } });

// Query results include the verified root hash
if (results.verifiedRootHash) {
  console.log('Data verified against root:', results.verifiedRootHash);
}

// For performance-critical scenarios, skip verification:
const unverifiedData = await client.getUnverified('dataset', 'key');
const unverifiedResults = await client.queryUnverified('dataset', { /* query */ });
```

## Data Operations

### Store Data

```typescript
// Store single item
await client.store('dataset-id', 'key', { field: 'value' });

// Batch store using collection helper
const collection = client.collection('dataset-id');
await collection.batchStore([
  { key: 'key1', value: { name: 'Item 1' } },
  { key: 'key2', value: { name: 'Item 2' } },
]);
```

### Retrieve Data

```typescript
// With automatic proof verification (secure by default)
const data = await client.get('dataset-id', 'key');

// Without verification (performance mode)
const data = await client.getUnverified('dataset-id', 'key');

// Get multiple with verification
const collection = client.collection('dataset-id');
const multiple = await collection.getMultiple(['key1', 'key2', 'key3']);
```

### Query Data

```typescript
// Query with automatic proof verification
const results = await client.query('dataset-id', {
  filters: { status: 'active', score: { $gte: 100 } },
  limit: 10,
  offset: 0,
});

console.log('Documents:', results.documents);
console.log('Total:', results.total);
console.log('Verified root:', results.verifiedRootHash);

// Query without verification
const results = await client.queryUnverified('dataset-id', {
  filters: { status: 'active' },
});
```

### Update and Delete

```typescript
await client.update('dataset-id', 'key', { field: 'new value' });
await client.delete('dataset-id', 'key');
```

### Historical Data Queries

Query data from verified checkpoints. Historical queries are routed to indexers who have declared availability for the checkpoint:

```typescript
// Get checkpoint state root for verification
const checkpoint = await client.data.getCheckpointStateRoot(
  'uniswap-v3',
  'a1b2c3d4...'
);
console.log('State root:', checkpoint.state_root);
console.log('Block range:', checkpoint.block_range);

// Query historical data (routed through consensus to indexer)
const result = await client.data.queryHistorical(
  'uniswap-v3',
  'a1b2c3d4...',
  {
    path: [[97, 112, 112, 115], [117, 115, 101, 114, 115]],
    key: [117, 115, 101, 114, 49, 50, 51],
    include_proof: true,
  }
);

console.log('Provider:', result.provider_did);
console.log('Data:', result.data);
console.log('State root:', result.state_root);

// Query with automatic proof verification against checkpoint state root
const verified = await client.data.queryHistoricalVerified(
  'uniswap-v3',
  'a1b2c3d4...',
  { path: [...], key: [...] }
);
// Throws if proof verification fails
```

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
await users.update('alice', { ...alice, score: 150 });
await users.delete('alice');

// Batch operations
await users.batchStore([
  { key: 'bob', value: { name: 'Bob' } },
  { key: 'charlie', value: { name: 'Charlie' } },
]);

// Query within collection
const highScorers = await users.query({
  filters: { score: { $gte: 100 } },
});

// Unverified variants available
const fast = await users.getUnverified('alice');
const fastQuery = await users.queryUnverified({ /* ... */ });
```

## Root Hash Verification

```typescript
// Get consensus-verified root hash (recommended for security)
const verifiedRoot = await client.getRootHash();

// Get local node's root hash (for debugging)
const localRoot = await client.getRootHashLocal();

// Compare to check sync status
if (verifiedRoot === localRoot) {
  console.log('Node is in sync with blockchain');
} else {
  console.log('Node has pending changes');
}
```

## Proof Verification API

All verification functions *bind the returned data to the proof*: every
document you pass in must deep-equal a value the proof actually commits to,
so a server cannot pair a valid proof with unrelated data. The computed root
hash must still be compared against a trusted source to establish that the
proven state is canonical.

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
  verifyQueryProof,
  verifyItemProof,
  verifyQueryResponse,
  computeProofRootHash,
  GroveDBProofVerifier,
} from '@willow-network/sdk';

// Verify a query proof; every document must be committed to by the proof
const rootHash = await verifyQueryProof(proofHex, documents);

// Verify a single item proof: enforces that the proof contains `key` at the
// given path AND that the proven payload deep-equals `value`
const rootHash = await verifyItemProof(proofHex, 'key', value, ['path', 'to', 'item']);

// Verify a QueryResponse object (binds response.documents)
const rootHash = await verifyQueryResponse(response);

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
const result = grovedb.verifyGroveDBProof(proofBytes);
// result: { rootHash: Uint8Array, results: Array<{ path, key, value, element }> }

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

// Verify a query proof against the light client's root hash
const result = await lightClient.verifyQueryProof(proof);

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

// Use with client
const client = new WillowClient({
  apiUrl: 'http://localhost:3031',
  did: didDocument.id,
  privateKey: wallet.privateKey, // 0x-prefixed Ethereum private key
});
```

## Registration

### Register Subgrove

A *subgrove* is Willow's on-chain unit of storage — a named subtree with a
schema and access lists. Data operations target a subgrove by id, and writes
fail until the subgrove is registered (and its registration fee paid by a
funded DID). `registerDataset` is a deprecated alias of `registerSubgrove`;
"subgrove" is the on-chain term.

```typescript
// Returns the consensus BroadcastResult (txHash, height, rawLog)
const result = await client.registerSubgrove({
  dataset_id: 'users',
  name: 'User Data',
  dataset_path: ['collections'],
  schema: {
    version: 1,
    fields: {
      name: { type: 'string' },
      score: { type: 'number' },
      active: { type: 'boolean' },
    },
    indexes: [
      { name: 'by_name', fields: ['name'], unique: false, type: 'hash' },
    ],
    required_fields: ['name'],
  },
  owner_did: didDocument.id,
  writers: [didDocument.id],
  readers: [],
});
```

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

## API Reference

### WillowClient

| Method | Description |
|--------|-------------|
| `init()` | Initialize with authentication |
| `registerDid(didDocument)` | Register a new DID |
| `registerSubgrove(request)` | Register a subgrove (returns the consensus `BroadcastResult`) |
| `deregisterSubgrove(subgroveId)` | Deregister a subgrove; remaining funding refunds to the owner |
| `store(datasetId, key, value)` | Store data |
| `get(datasetId, key)` | Get data with proof verification |
| `getUnverified(datasetId, key)` | Get data without verification |
| `update(datasetId, key, value)` | Update data |
| `delete(datasetId, key)` | Delete data |
| `query(datasetId, query)` | Query with proof verification |
| `queryUnverified(datasetId, query)` | Query without verification |
| `sqlQuery(subgroveId, sql, options?)` | SQL query routed to indexer or validator |
| `graphqlQuery(subgroveId, query, options?)` | GraphQL query routed to indexer or validator |
| `getProof(datasetId, key)` | Get raw Merkle proof |
| `getRootHash()` | Get consensus-verified root hash |
| `getRootHashLocal()` | Get local node's root hash |
| `collection(datasetId)` | Create collection helper |
| `auth.setIdentity(did, privateKey, publicKeyId)` | Set identity for per-request signing |
| `auth.hasIdentity()` | Check whether an identity is set |

### Data Client Historical Methods

| Method | Description |
|--------|-------------|
| `data.getCheckpointStateRoot(subgroveId, checkpointId)` | Get checkpoint state root for verification |
| `data.queryHistorical(subgroveId, checkpointId, query)` | Query historical checkpoint data |
| `data.queryHistoricalVerified(subgroveId, checkpointId, query)` | Query with automatic proof verification |

### Proof Verification Functions

| Function | Description |
|----------|-------------|
| `verifyQueryProof(proofHex, documents, options?)` | Verify query proof and bind documents to it, returns root hash |
| `verifyItemProof(proofHex, key, value, path, options?)` | Verify item proof and bind key/value/path to it, returns root hash |
| `verifyQueryResponse(response)` | Verify QueryResponse object, binding its documents |
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
| `isValidDid(did)` | Validate DID format |

## Security Model

The SDK provides two levels of security:

1. **Full Local Verification** (default)
   - Pure TypeScript GroveDB proof verification
   - BLAKE3 hashing, Merk proof execution
   - Binds returned documents to the proof
   - Compares against the consensus root hash, which is currently fetched
     from the configured RPC endpoint (see [Light Client](#light-client-experimental)
     for the exact trust assumption)

2. **Unverified** (opt-in via `*Unverified` methods)
   - Trusts the node completely
   - Maximum performance
   - Use only with trusted nodes

## License

MIT
