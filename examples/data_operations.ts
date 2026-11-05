/**
 * Willow TypeScript SDK - Data Operations Example
 *
 * Comprehensive data operations:
 * 1. Store single items
 * 2. Batch store multiple items
 * 3. Get single item (with proof verification)
 * 4. Get unverified (performance mode)
 * 5. Get multiple items
 * 6. Query with filters / range / fulltext / proof
 * 7. Update items
 * 8. Delete items
 *
 * All reads include automatic proof verification by default.
 *
 * Prerequisites:
 * - npm install @willow-network/sdk
 * - A local Willow node with its API server on port 3031 — see the docs
 *   for node setup: https://willow.tech
 *
 * Run with: npx ts-node examples/data_operations.ts
 */

import {
  WillowClient,
  TransactionStatus,
  generateEd25519KeyPair,
  createDidFromPublicKey,
  QueryRequest,
} from '../src';

async function main() {
  console.log('Willow SDK - Data Operations Example');
  console.log('====================================\n');

  const client = new WillowClient({ apiUrl: 'http://localhost:3031' });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  // Self-certifying DID — id is derived from the key (see createDidFromPublicKey).
  const didDocument = createDidFromPublicKey(publicKey, 'Ed25519');
  const did = didDocument.id;
  const publicKeyId = didDocument.publicKeys[0].id;

  console.log('Setting up identity...');
  // A real deployment funds `did` (>= the registration fee) before registering.
  try {
    // The DID's registration is signed by its own key.
    client.auth.setIdentity(did, privateKey, publicKeyId);
    await client.registerDid(didDocument);
    console.log(`Authenticated as: ${did}\n`);
  } catch (error) {
    console.log(`Note: ${error}\n`);
  }

  // The subgrove "products" needs to be registered and funded before writes
  // succeed; see app_registration.ts. Errors fall back to printing a note.
  const datasetId = 'products';
  const products = client.collection(datasetId);

  // 1. Store single item
  console.log('1. Store single item...');
  try {
    await products.store('prod-001', {
      id: 'prod-001',
      name: 'Laptop Pro',
      category: 'electronics',
      price: 1299.99,
      stock: 50,
      tags: ['laptop', 'computer', 'portable'],
      created_at: Date.now(),
    });
    console.log('   Stored: prod-001 (Laptop Pro)\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 2. Store several items. Each key is its own StoreData transaction; the
  //    client gives writes in flight together distinct nonces (up to 24 per
  //    identity), so they can be sent at once.
  console.log('2. Store several items...');
  const batchProducts = [
    { key: 'prod-002', value: { id: 'prod-002', name: 'Wireless Mouse', category: 'electronics', price: 49.99, stock: 200 } },
    { key: 'prod-003', value: { id: 'prod-003', name: 'USB-C Cable', category: 'accessories', price: 19.99, stock: 500 } },
    { key: 'prod-004', value: { id: 'prod-004', name: 'Monitor 27"', category: 'electronics', price: 399.99, stock: 30 } },
    { key: 'prod-005', value: { id: 'prod-005', name: 'Mechanical Keyboard', category: 'electronics', price: 149.99, stock: 75 } },
  ];
  try {
    const results = await Promise.all(
      batchProducts.map(({ key, value }) =>
        client.consensus.storeData(datasetId, key, value, did, client.auth.transactionSigner()),
      ),
    );
    for (const result of results) {
      // A write refused at CheckTx, or whose outcome is pending, has no tx
      // hash to wait on; its `submission` can be confirmed or posted again.
      if (!result.success) throw new Error(`a write did not go through: ${result.errorMessage}`);
      // A write refused in its block lands too, as FAILED.
      if ((await client.consensus.waitForTransaction(result.txHash!)) !== TransactionStatus.SUCCESS) {
        throw new Error(`a write was refused in its block: ${result.txHash}`);
      }
    }
    console.log(`   Stored ${batchProducts.length} products\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 3. Get single item (with proof verification — the SDK fetches the
  // proof, verifies it against the consensus-verified app_hash, and only
  // then returns the DataRecord).
  console.log('3. Get single item (with proof verification)...');
  try {
    const result = await products.get('prod-001');
    console.log('   Data retrieved and VERIFIED:');
    console.log(`   Name:  ${result.name}`);
    console.log(`   Price: $${result.price}`);
    console.log(`   Stock: ${result.stock}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 4. Get single item without verification (faster)
  console.log('4. Get single item (without verification)...');
  try {
    const result = await products.getUnverified('prod-001');
    console.log('   Data retrieved (unverified, faster):');
    console.log(`   Name:  ${result.name}`);
    console.log(`   Price: $${result.price}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 5. Get multiple items (returns Record<key, DataRecord>)
  console.log('5. Get multiple items...');
  try {
    const results = await products.getMultiple(['prod-001', 'prod-002', 'prod-003']);
    const entries = Object.entries(results);
    console.log(`   Retrieved ${entries.length} items:`);
    entries.forEach(([key, item]) => {
      console.log(`   - ${key}: ${item?.name ?? 'Unknown'} ($${item?.price ?? 0})`);
    });
    console.log();
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 6. Queries
  console.log('6. Query with filters...');

  console.log('   6a. Products in "electronics" category:');
  try {
    const electronicsQuery: QueryRequest = {
      filters: { category: 'electronics' },
      limit: 10,
    };
    const results = await products.query(electronicsQuery);
    console.log(`       Found ${results.documents.length} electronics products`);
    results.documents.forEach((doc: any) => {
      console.log(`       - ${doc.name}: $${doc.price}`);
    });
  } catch (error) {
    console.log(`       Note: ${error}`);
  }

  // The API applies one exact-match filter and a sort, and no filter
  // operator or search: a verified query asking for one throws
  // QUERY_NOT_VERIFIABLE. Narrow the verified result yourself.
  console.log('\n   6b. Electronics between $50-$500, sorted by price:');
  try {
    const sortedQuery: QueryRequest = {
      filters: { category: 'electronics' },
      sort: { field: 'price', order: 'asc' },
    };
    const results = await products.query(sortedQuery);
    const inRange = results.documents.filter((doc: any) => doc.price >= 50 && doc.price <= 500);
    console.log(`       Found ${inRange.length} products in price range`);
    inRange.forEach((doc: any) => {
      console.log(`       - ${doc.name}: $${doc.price}`);
    });
  } catch (error) {
    console.log(`       Note: ${error}`);
  }

  console.log('\n   6c. Electronics whose name mentions "keyboard":');
  try {
    const results = await products.query({ filters: { category: 'electronics' } });
    const matching = results.documents.filter((doc: any) =>
      String(doc.name).toLowerCase().includes('keyboard'),
    );
    console.log(`       Found ${matching.length} matching products`);
    matching.forEach((doc: any) => {
      console.log(`       - ${doc.name}`);
    });
  } catch (error) {
    console.log(`       Note: ${error}`);
  }

  console.log('\n   6d. Query with cryptographic proof attached:');
  try {
    const proofQuery: QueryRequest = {
      filters: { category: 'electronics' },
      include_proof: true,
      limit: 5,
    };
    const results = await products.query(proofQuery);
    console.log(`       Found ${results.documents.length} documents`);
    if (results.proof) {
      console.log(`       Proof: ${results.proof.length / 2} bytes`);
    }
    if (results.verifiedRootHash) {
      console.log(`       Verified root: ${results.verifiedRootHash.substring(0, 32)}...`);
    }
  } catch (error) {
    console.log(`       Note: ${error}`);
  }
  console.log();

  // Changing or deleting an existing key takes an UpdateData or DeleteData
  // transaction, which this SDK does not build.

  // 7. Get proof separately (returns the hex string directly)
  console.log('7. Get proof for item...');
  try {
    const proofHex = await products.getProof('prod-001');
    console.log(`   Proof: ${proofHex.length / 2} bytes`);
    console.log(`   Proof (first 64 chars): ${proofHex.substring(0, 64)}...\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('Data Operations Summary');
  console.log('=======================');
  console.log('CRUD:');
  console.log('  - store(key, value): create a key (one transaction)');
  console.log('  - get(key): retrieve with proof verification (secure)');
  console.log('  - getUnverified(key): retrieve without verification (fast)');
  console.log('  - getMultiple(keys): batch retrieve (an absent key must be proven absent)\n');

  console.log('Query (verified as the whole result):');
  console.log('  - query({ filters: { field: value } }): one exact-match field');
  console.log('  - query({ sort, limit, offset }): sort and pagination');
  console.log('  - ranges and text matches: filter the verified documents yourself\n');

  console.log('Data operations example complete!');
}

main().catch(console.error);
