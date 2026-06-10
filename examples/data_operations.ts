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
  generateEd25519KeyPair,
  QueryRequest,
} from '../src';

async function main() {
  console.log('Willow SDK - Data Operations Example');
  console.log('====================================\n');

  const client = new WillowClient({ apiUrl: 'http://localhost:3031' });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  const timestamp = Date.now();
  const did = `did:willow:data_demo_${timestamp}`;
  const publicKeyId = `${did}#key-1`;

  const didDocument = {
    id: did,
    publicKeys: [{ id: publicKeyId, type: 'Ed25519', publicKeyHex: publicKey }],
    created: timestamp,
    updated: timestamp,
  };

  console.log('Setting up identity...');
  try {
    await client.registerDid(didDocument);
    client.auth.setIdentity(did, privateKey, publicKeyId);
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

  // 2. Batch store
  console.log('2. Batch store multiple items...');
  const batchProducts = [
    { key: 'prod-002', value: { id: 'prod-002', name: 'Wireless Mouse', category: 'electronics', price: 49.99, stock: 200 } },
    { key: 'prod-003', value: { id: 'prod-003', name: 'USB-C Cable', category: 'accessories', price: 19.99, stock: 500 } },
    { key: 'prod-004', value: { id: 'prod-004', name: 'Monitor 27"', category: 'electronics', price: 399.99, stock: 30 } },
    { key: 'prod-005', value: { id: 'prod-005', name: 'Mechanical Keyboard', category: 'electronics', price: 149.99, stock: 75 } },
  ];
  try {
    await products.batchStore(batchProducts);
    console.log(`   Batch stored ${batchProducts.length} products\n`);
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

  console.log('\n   6b. Products between $50-$500:');
  try {
    const priceQuery: QueryRequest = {
      filters: { price: { $gte: 50, $lte: 500 } },
      sort: { field: 'price', order: 'asc' },
      limit: 10,
    };
    const results = await products.query(priceQuery);
    console.log(`       Found ${results.documents.length} products in price range`);
    results.documents.forEach((doc: any) => {
      console.log(`       - ${doc.name}: $${doc.price}`);
    });
  } catch (error) {
    console.log(`       Note: ${error}`);
  }

  console.log('\n   6c. Search for "keyboard":');
  try {
    const searchQuery: QueryRequest = {
      search: { field: 'name', query: 'keyboard' },
      limit: 10,
    };
    const results = await products.query(searchQuery);
    console.log(`       Found ${results.documents.length} matching products`);
    results.documents.forEach((doc: any) => {
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

  // 7. Update item
  console.log('7. Update item...');
  try {
    await products.update('prod-001', {
      id: 'prod-001',
      name: 'Laptop Pro',
      category: 'electronics',
      price: 1199.99,
      stock: 45,
      tags: ['laptop', 'computer', 'portable', 'on-sale'],
      on_sale: true,
      updated_at: Date.now(),
    });
    console.log('   Updated prod-001 (price reduced to $1199.99, on_sale=true)\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('   Verifying update...');
  try {
    const updated = await products.get('prod-001');
    console.log(`   New price: $${updated.price}`);
    console.log(`   On sale: ${updated.on_sale}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 8. Delete item
  console.log('8. Delete item...');
  try {
    await products.delete('prod-005');
    console.log('   Deleted: prod-005 (Mechanical Keyboard)\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 9. Get proof separately (returns the hex string directly)
  console.log('9. Get proof for item...');
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
  console.log('  - store(key, value): create or overwrite');
  console.log('  - batchStore(items): store many atomically');
  console.log('  - get(key): retrieve with proof verification (secure)');
  console.log('  - getUnverified(key): retrieve without verification (fast)');
  console.log('  - getMultiple(keys): batch retrieve');
  console.log('  - update(key, value): update existing item');
  console.log('  - delete(key): remove item\n');

  console.log('Query:');
  console.log('  - query({ filters }): filter by field values');
  console.log('  - query({ filters: { field: { $gte, $lte } } }): range');
  console.log('  - query({ search: { field, query } }): text search');
  console.log('  - query({ sort, limit, offset }): pagination\n');

  console.log('Data operations example complete!');
}

main().catch(console.error);
