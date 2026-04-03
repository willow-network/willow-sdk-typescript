/**
 * Willow TypeScript SDK - Data Operations Example
 *
 * This example demonstrates comprehensive data operations:
 * 1. Store single items
 * 2. Batch store multiple items
 * 3. Get single item (with proof verification)
 * 4. Get unverified (performance mode)
 * 5. Get multiple items
 * 6. Query with filters
 * 7. Update items
 * 8. Delete items
 *
 * All operations include automatic proof verification by default.
 *
 * Prerequisites:
 * - npm install @willow/sdk
 * - Run a local Willow node: ./scripts/start_node.sh
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

  // Setup: Create client and authenticate
  const client = new WillowClient({
    apiUrl: 'http://localhost:3031',
  });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  const timestamp = Date.now();
  const did = `did:willow:data_demo_${timestamp}`;
  const publicKeyId = `${did}#key-1`;

  const didDocument = {
    id: did,
    controller: did,
    verificationMethod: [
      {
        id: publicKeyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: `z${publicKey}`,
      },
    ],
    authentication: [publicKeyId],
    assertionMethod: [publicKeyId],
    publicKeys: [
      {
        id: publicKeyId,
        type: 'Ed25519',
        publicKeyHex: publicKey,
      },
    ],
  };

  console.log('Setting up identity...');
  try {
    await client.registerDid(didDocument);
    await client.auth.login(did, privateKey, publicKeyId);
    console.log(`Authenticated as: ${did}\n`);
  } catch (error) {
    console.log(`Note: ${error}\n`);
  }

  // Use test dataset (would be registered in production)
  
  const datasetId = 'products';

  // Create a collection helper for cleaner syntax
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

  // 2. Batch store multiple items
  console.log('2. Batch store multiple items...');
  const batchProducts = [
    {
      key: 'prod-002',
      value: {
        id: 'prod-002',
        name: 'Wireless Mouse',
        category: 'electronics',
        price: 49.99,
        stock: 200,
        tags: ['mouse', 'wireless', 'peripheral'],
        created_at: Date.now(),
      },
    },
    {
      key: 'prod-003',
      value: {
        id: 'prod-003',
        name: 'USB-C Cable',
        category: 'accessories',
        price: 19.99,
        stock: 500,
        tags: ['cable', 'usb-c', 'charging'],
        created_at: Date.now(),
      },
    },
    {
      key: 'prod-004',
      value: {
        id: 'prod-004',
        name: 'Monitor 27"',
        category: 'electronics',
        price: 399.99,
        stock: 30,
        tags: ['monitor', 'display', '4k'],
        created_at: Date.now(),
      },
    },
    {
      key: 'prod-005',
      value: {
        id: 'prod-005',
        name: 'Mechanical Keyboard',
        category: 'electronics',
        price: 149.99,
        stock: 75,
        tags: ['keyboard', 'mechanical', 'rgb'],
        created_at: Date.now(),
      },
    },
  ];

  try {
    await products.batchStore(batchProducts);
    console.log(`   Batch stored ${batchProducts.length} products\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 3. Get single item with proof verification (default)
  console.log('3. Get single item (with proof verification)...');
  try {
    const result = await products.get('prod-001');
    console.log('   Data retrieved and VERIFIED:');
    console.log(`   Name: ${result.data.name}`);
    console.log(`   Price: $${result.data.price}`);
    console.log(`   Stock: ${result.data.stock}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 4. Get single item without verification (faster)
  console.log('4. Get single item (without verification)...');
  try {
    const result = await products.getUnverified('prod-001');
    console.log('   Data retrieved (unverified, faster):');
    console.log(`   Name: ${result.data.name}`);
    console.log(`   Price: $${result.data.price}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 5. Get multiple items
  console.log('5. Get multiple items...');
  try {
    const results = await products.getMultiple(['prod-001', 'prod-002', 'prod-003']);
    console.log(`   Retrieved ${results.length} items:`);
    results.forEach((item: any) => {
      console.log(`   - ${item.data?.name || 'Unknown'}: $${item.data?.price || 0}`);
    });
    console.log();
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 6. Query with filters
  console.log('6. Query with filters...');

  // 6a. Query by category
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

  // 6b. Query by price range
  console.log('\n   6b. Products between $50-$500:');
  try {
    const priceQuery: QueryRequest = {
      filters: {
        price: { $gte: 50, $lte: 500 },
      },
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

  // 6c. Query with text search
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

  // 6d. Query with proof
  console.log('\n   6d. Query with cryptographic proof:');
  try {
    const proofQuery: QueryRequest = {
      filters: { category: 'electronics' },
      include_proof: true,
      limit: 5,
    };
    const results = await products.query(proofQuery);
    console.log(`       Found ${results.documents.length} documents`);
    if (results.proof) {
      console.log(`       Proof included: ${results.proof.length / 2} bytes`);
    }
    if (results.root_hash) {
      console.log(`       Root hash: ${results.root_hash.substring(0, 32)}...`);
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
      price: 1199.99, // Price reduced!
      stock: 45,
      tags: ['laptop', 'computer', 'portable', 'on-sale'],
      on_sale: true,
      updated_at: Date.now(),
    });
    console.log('   Updated prod-001:');
    console.log('   - Price reduced from $1299.99 to $1199.99');
    console.log('   - Added "on-sale" tag');
    console.log('   - Set on_sale: true\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // Verify the update
  console.log('   Verifying update...');
  try {
    const updated = await products.get('prod-001');
    console.log(`   New price: $${updated.data.price}`);
    console.log(`   On sale: ${updated.data.on_sale}\n`);
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

  // Verify deletion
  console.log('   Verifying deletion...');
  try {
    await products.get('prod-005');
    console.log('   Item still exists (unexpected)\n');
  } catch (error) {
    console.log('   Item no longer exists (expected)\n');
  }

  // 9. Get proof separately
  console.log('9. Get proof for item...');
  try {
    const proof = await products.getProof('prod-001');
    console.log(`   Proof retrieved: ${proof.length / 2} bytes`);
    console.log(`   Proof (first 64 chars): ${proof.substring(0, 64)}...\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // Summary
  console.log('Data Operations Summary');
  console.log('=======================');
  console.log('CRUD Operations:');
  console.log('  - store(key, value): Create or overwrite');
  console.log('  - batchStore(items): Store multiple items atomically');
  console.log('  - get(key): Retrieve with proof verification (secure)');
  console.log('  - getUnverified(key): Retrieve without verification (fast)');
  console.log('  - getMultiple(keys): Batch retrieve');
  console.log('  - update(key, value): Update existing item');
  console.log('  - delete(key): Remove item\n');

  console.log('Query Operations:');
  console.log('  - query({ filters }): Filter by field values');
  console.log('  - query({ filters: { field: { $gte, $lte } } }): Range queries');
  console.log('  - query({ search: { field, query } }): Text search');
  console.log('  - query({ sort, limit, offset }): Pagination\n');

  console.log('Verification:');
  console.log('  - get() and query() include automatic verification');
  console.log('  - getUnverified() and queryUnverified() skip verification');
  console.log('  - getProof() retrieves proof separately\n');

  console.log('Data operations example complete!');
}

// Run the example
main().catch(console.error);
