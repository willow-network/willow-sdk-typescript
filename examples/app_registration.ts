/**
 * Willow TypeScript SDK - Dataset Registration Example
 *
 * Demonstrates how to:
 * 1. Define schemas
 * 2. Register a dataset (subgrove + schema)
 * 3. Inspect dataset access permissions
 *
 * Prerequisites:
 * - npm install @willow-network/sdk
 * - A local Willow node with its API server on port 3031 — see the docs
 *   for node setup: https://willow.tech
 *
 * Run with: npx ts-node examples/app_registration.ts
 */

import {
  WillowClient,
  generateEd25519KeyPair,
  createDidFromPublicKey,
  RegisterSubgroveRequest,
  SchemaDefinition,
} from '../src';

async function main() {
  console.log('Willow SDK - Dataset Registration Example');
  console.log('=========================================\n');

  const client = new WillowClient({ apiUrl: 'http://localhost:3031' });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  // The DID id is derived from (and bound to) the key — it is not chosen.
  const didDocument = createDidFromPublicKey(publicKey, 'Ed25519');
  const did = didDocument.id;
  const publicKeyId = didDocument.publicKeys[0].id;

  console.log('Setting up identity...');
  // NOTE: registration is paid from `did`'s own balance, so a real deployment
  // must fund `did` (transfer >= the registration fee) before this call.
  try {
    // The DID's registration is signed by its own key.
    client.auth.setIdentity(did, privateKey, publicKeyId);
    await client.registerDid(didDocument);
    console.log(`Authenticated as: ${did}\n`);
  } catch (error) {
    console.log(`Note: ${error}\n`);
  }

  // 1. Products dataset
  console.log('1. Registering "products" dataset...');
  const productsSchema: SchemaDefinition = {
    version: 1,
    fields: {
      sku: 'string',
      name: 'string',
      description: 'string',
      category: 'string',
      price: 'number',
      stock: 'number',
      rating: 'number',
      tags: 'array',
      images: 'array',
      specifications: 'object',
      created_at: 'number',
    },
    required_fields: ['sku', 'name', 'category', 'price'],
  };

  const productsDataset: RegisterSubgroveRequest = {
    dataset_id: 'products',
    name: 'Product Catalog',
    schema: productsSchema,
    owner_did: did,
    writers: [did],
    readers: [],
  };

  try {
    const result = await client.registerSubgrove(productsDataset);
    console.log('   Products subgrove registered');
    console.log(`   Tx hash: ${result.txHash}`);
    console.log();
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 2. Orders dataset (private)
  console.log('2. Registering "orders" dataset (private)...');
  const ordersSchema: SchemaDefinition = {
    version: 1,
    fields: {
      order_id: 'string',
      customer_did: 'string',
      items: 'array',
      total: 'number',
      status: 'string',
      shipping_address: 'object',
      created_at: 'number',
      updated_at: 'number',
    },
    required_fields: ['order_id', 'customer_did', 'items', 'total', 'status'],
  };

  const ordersDataset: RegisterSubgroveRequest = {
    dataset_id: 'orders',
    name: 'Customer Orders',
    schema: ordersSchema,
    owner_did: did,
    writers: [did],
    readers: [did],
  };

  try {
    const result = await client.registerSubgrove(ordersDataset);
    console.log('   Orders subgrove registered');
    console.log(`   Tx hash: ${result.txHash}`);
    console.log('   Access: private (owner only)\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 3. Users dataset (public read)
  console.log('3. Registering "users" dataset (public profiles)...');
  const usersSchema: SchemaDefinition = {
    version: 1,
    fields: {
      user_did: 'string',
      username: 'string',
      display_name: 'string',
      bio: 'string',
      avatar_url: 'string',
      joined_at: 'number',
      reputation: 'number',
    },
    required_fields: ['user_did', 'username'],
  };

  const usersDataset: RegisterSubgroveRequest = {
    dataset_id: 'users',
    name: 'User Profiles',
    schema: usersSchema,
    owner_did: did,
    writers: [did],
    readers: [],
  };

  try {
    const result = await client.registerSubgrove(usersDataset);
    console.log('   Users subgrove registered');
    console.log(`   Tx hash: ${result.txHash}`);
    console.log('   Access: public read, owner write\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('Summary');
  console.log('=======');
  console.log('  - products: public catalog');
  console.log('  - orders:   private order records');
  console.log('  - users:    public profiles, owner-managed');
  console.log();
  console.log('Index types used:');
  console.log('  - unique:   no duplicates (sku, order_id, username)');
  console.log('  - hash:     fast equality (category, status, customer_did)');
  console.log('  - range:    numeric comparisons (price, rating, date)');
  console.log('  - fulltext: text search (name + description)');
  console.log('  - compound: multi-field (category + price)');
  console.log();
  console.log('Subgrove registration example complete!');
}

main().catch(console.error);
