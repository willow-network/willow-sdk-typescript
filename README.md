# Willow TypeScript SDK

TypeScript/JavaScript SDK for interacting with the Willow decentralized data infrastructure protocol. Provides cryptographic proof verification for all data operations using a pure TypeScript implementation of GroveDB verification.

## Features

- **Secure by Default**: All data operations automatically verify cryptographic proofs
- **Full Local Verification**: Pure TypeScript GroveDB proof verification (BLAKE3, Merk proofs)
- **DID Authentication**: Ed25519 and secp256k1 (Ethereum-compatible) signature support
- **Light Client**: Optional CometBFT light client for trustless header verification
- **Multiple Verification Strategies**: Local full, local basic, or server-assisted verification
- **File Storage**: Upload, download, list, and delete files with chunk Merkle verification
- **File Encryption**: XChaCha20-Poly1305 encryption/decryption for private files
- **Collection Helpers**: Convenient API for working with subgrove/dataset pairs

## Installation

```bash
npm install @willow/sdk
# or
yarn add @willow/sdk
# or
pnpm add @willow/sdk
```

## Quick Start

```typescript
import { WillowClient, generateEd25519KeyPair } from '@willow/sdk';
import { generateWallet, createDidFromWallet } from '@willow/sdk';

// 1. Generate a wallet and DID
const wallet = generateWallet();
const didDocument = createDidFromWallet(wallet);

// 2. Initialize the client
const client = new WillowClient({
  apiUrl: 'http://localhost:3031',
  did: didDocument.id,
  privateKey: wallet.privateKey,
});

// 3. Register and authenticate
await client.registerDid(didDocument);
await client.init();

// 4. Store data
await client.store('users', 'alice', {
  name: 'Alice',
  score: 100,
});

// 5. Retrieve data (automatically verified!)
const data = await client.get('users', 'alice');
console.log(data);
```

## Secure by Default: Automatic Proof Verification

All data operations automatically verify cryptographic proofs against the consensus-verified root hash:

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

For easier data management with a specific subgrove/dataset:

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

### Configure Verification Strategy

```typescript
import { configureProofVerification } from '@willow/sdk';

// Use local full verification (default)
configureProofVerification({
  serverAssisted: false,
});

// Use server-assisted verification
configureProofVerification({
  serverAssisted: true,
  apiUrl: 'http://localhost:3031',
});

// Verify against a known root hash
configureProofVerification({
  expectedRootHash: knownRootHash,
});
```

### Manual Proof Verification

```typescript
import {
  verifyQueryProof,
  verifyItemProof,
  verifyQueryResponse,
  verifyProofAdvanced,
  extractRootHashFromProof,
} from '@willow/sdk';

// Verify a query proof
const rootHash = await verifyQueryProof(proofHex, documents);

// Verify a single item proof
const rootHash = await verifyItemProof(proofHex, 'key', value, ['path', 'to', 'item']);

// Verify a query response object
const rootHash = await verifyQueryResponse(response);

// Advanced verification with options
const result = await verifyProofAdvanced(proofHex, documents, {
  serverAssisted: true,
  expectedRootHash: expectedRoot,
});
// result: { valid: boolean, rootHash: string, method: string }

// Extract root hash only (fast)
const rootHash = await extractRootHashFromProof(proofHex);
```

## GroveDB Verification Module

For low-level proof verification:

```typescript
import * as grovedb from '@willow/sdk/grovedb';

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

## Light Client (Advanced)

For trustless verification via CometBFT light client protocol:

```typescript
import { LightClient, LightClientConfigBuilder } from '@willow/sdk';

// Configure light client
const config = new LightClientConfigBuilder()
  .chainId('willow-mainnet')
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

// Verify a query proof against consensus
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
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from '@willow/sdk';

// Generate key pair
const { privateKey, publicKey } = generateEd25519KeyPair();

// Sign a message
const signature = signEd25519('Hello, Willow!', privateKey);

// Verify signature
const isValid = verifyEd25519('Hello, Willow!', signature, publicKey);
```

### Secp256k1 (Ethereum-compatible)

```typescript
import { generateWallet, createDidFromWallet } from '@willow/sdk';

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


```typescript
  name: 'My Application',
  description: 'Built with Willow',
  owner_did: didDocument.id,
  admins: [],
});
```

### Register Dataset

```typescript
const dataset = await client.registerDataset({
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
      { name: 'by_name', fields: ['name'], unique: false },
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
import { WillowError } from '@willow/sdk';

try {
  await client.get('subgrove', 'dataset', 'key');
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

| `registerDataset(request)` | Register a dataset |
| `store(datasetId, key, value)` | Store data |
| `get(datasetId, key)` | Get data with proof verification |
| `getUnverified(datasetId, key)` | Get data without verification |
| `update(datasetId, key, value)` | Update data |
| `delete(datasetId, key)` | Delete data |
| `query(datasetId, query)` | Query with proof verification |
| `queryUnverified(datasetId, query)` | Query without verification |
| `getProof(datasetId, key)` | Get raw Merkle proof |
| `getRootHash()` | Get consensus-verified root hash |
| `getRootHashLocal()` | Get local node's root hash |
| `collection(datasetId)` | Create collection helper |
| `getSession()` | Get current session |

### Data Client Historical Methods

| Method | Description |
|--------|-------------|
| `data.getCheckpointStateRoot(subgroveId, checkpointId)` | Get checkpoint state root for verification |
| `data.queryHistorical(subgroveId, checkpointId, query)` | Query historical checkpoint data |
| `data.queryHistoricalVerified(subgroveId, checkpointId, query)` | Query with automatic proof verification |

### Proof Verification Functions

| Function | Description |
|----------|-------------|
| `verifyQueryProof(proofHex, documents)` | Verify query proof, returns root hash |
| `verifyItemProof(proofHex, key, value, path)` | Verify item proof, returns root hash |
| `verifyQueryResponse(response)` | Verify QueryResponse object |
| `verifyProofAdvanced(proofHex, documents, options)` | Advanced verification with options |
| `extractRootHashFromProof(proofHex)` | Extract root hash without full verification |
| `configureProofVerification(options)` | Configure global verification strategy |

### Utilities

| Function | Description |
|----------|-------------|
| `generateWallet()` | Generate Ethereum wallet |
| `createDidFromWallet(wallet)` | Create DID from wallet |
| `generateEd25519KeyPair()` | Generate Ed25519 key pair |
| `signEd25519(message, privateKey)` | Sign with Ed25519 |
| `verifyEd25519(message, signature, publicKey)` | Verify Ed25519 signature |
| `isValidDid(did)` | Validate DID format |
| `generateId(prefix?)` | Generate unique ID |

## Security Model

The SDK provides three levels of security:

1. **Full Local Verification** (default)
   - Pure TypeScript GroveDB proof verification
   - BLAKE3 hashing, Merk proof execution
   - Compares against consensus root hash

2. **Server-Assisted Verification**
   - Delegates verification to node's native Rust implementation
   - Uses `/verify-proof` endpoint
   - More accurate but requires network round-trip

3. **Unverified** (opt-in via `*Unverified` methods)
   - Trusts the node completely
   - Maximum performance
   - Use only with trusted nodes

## License

MIT
