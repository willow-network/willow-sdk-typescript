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
// Store a new key: one StoreData transaction
await client.store('dataset-id', 'key', { field: 'value' });
```

Each key is written by its own transaction, sent through `POST /tx/submit`;
the API has no REST route for data writes. `store` reads the account's nonce
from the chain, so send a write after the previous one has landed:

```typescript
for (const { key, value } of records) {
  const result = await client.consensus.storeData(
    'dataset-id', key, value, client.auth.getDid()!, client.auth.transactionSigner(),
  );
  await client.consensus.waitForTransaction(result.txHash!);
}
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

Changing an existing key takes an UpdateData transaction, and deleting one a
DeleteData transaction. This SDK builds neither: a StoreData of an existing
key is refused, and `client.update`, `client.delete`, `data.updateData`, and
`data.deleteData` throw `UNSUPPORTED_OPERATION` without sending anything, as
do `data.storeData` and `batchStore`, which have no per-key transaction.

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
- RevokeSubgroveKey is signed over `RevokeSubgroveKey:<subgrove id>:<revokee DID>:<sender DID>:<nonce>`, which binds every field.
- A DID registration (`client.registerDid`, `consensus.registerDid`) is signed over the JSON text of the DID document as the chain's `DidDocument` writes it (its fields in order, absent options as `null`), at nonce 1. `registerDidSignMessage(tx)` returns it.

`registerSubgroveSignMessage(tx)`, `grantSubgroveKeySignMessage(tx)`, `rotateSubgroveKeySignMessage(tx)`, and `unregisterStorageNodeSignMessage(tx)` return the exact message for a transaction.

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
| `registerDid(didDocument)` | Register the identity's DID by a RegisterDid transaction (returns the consensus `BroadcastResult`) |
| `registerSubgrove(request)` | Register a subgrove (returns the consensus `BroadcastResult`) |
| `deregisterSubgrove(subgroveId)` | Deregister a subgrove; remaining funding refunds to the owner |
| `store(datasetId, key, value)` | Store a new key by a StoreData transaction |
| `get(datasetId, key)` | Get data with proof verification |
| `getUnverified(datasetId, key)` | Get data without verification |
| `update(datasetId, key, value)` | Throws `UNSUPPORTED_OPERATION` (see [Update and Delete](#update-and-delete)) |
| `delete(datasetId, key)` | Throws `UNSUPPORTED_OPERATION` |
| `query(datasetId, query)` | Query with proof verification |
| `queryUnverified(datasetId, query)` | Query without verification |
| `sqlQuery(subgroveId, sql, options?)` | SQL query routed to indexer or validator |
| `graphqlQuery(subgroveId, query, options?)` | GraphQL query routed to indexer or validator |
| `getProof(datasetId, key)` | Get raw Merkle proof |
| `getRootHash()` | Get consensus-verified root hash |
| `getRootHashLocal()` | Get local node's root hash |
| `collection(datasetId)` | Create collection helper |
| `auth.setIdentity(did, privateKey, publicKeyId, algorithm?)` | Set the identity that signs transactions and requests |
| `auth.transactionSigner()` | The identity as a transaction signer, with its algorithm's sign function |
| `auth.hasIdentity()` | Check whether an identity is set |
| `auth.signRequestWithNonce(method, pathAndQuery, body?)` | Nonce-form signature headers for a request (see [Request signing](#request-signing)) |
| `auth.signRequest(method, path)` | Older-form signature headers |

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
| `unregisterStorageNodeSignMessage(tx)` | The message a storage node's removal signs |
| `registerDidSignMessage(tx)` | The message a DID registration signs |
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
