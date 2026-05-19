/**
 * Willow TypeScript SDK - Dataset Registration Example
 *
 * Demonstrates how to:
 * 1. Define schemas with multiple index types
 * 2. Register a dataset (subgrove + schema)
 * 3. Inspect dataset access permissions
 *
 * Prerequisites:
 * - npm install @willow/sdk
 * - Run a local Willow node: ./scripts/start_node.sh
 *
 * Run with: npx ts-node examples/app_registration.ts
 */

import {
  WillowClient,
  generateEd25519KeyPair,
  RegisterDatasetRequest,
  SchemaDefinition,
} from '../src';

async function main() {
  console.log('Willow SDK - Dataset Registration Example');
  console.log('=========================================\n');

  const client = new WillowClient({ apiUrl: 'http://localhost:3031' });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  const timestamp = Date.now();
  const did = `did:willow:owner_${timestamp}`;
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

  // 1. Products dataset
  console.log('1. Registering "products" dataset...');
  const productsSchema: SchemaDefinition = {
    version: 1,
    fields: {
      sku: { type: 'string', indexed: true, required: true },
      name: { type: 'string', indexed: true, required: true },
      description: { type: 'string', indexed: true },
      category: { type: 'string', indexed: true, required: true },
      price: { type: 'number', indexed: true, required: true },
      stock: { type: 'number', indexed: true },
      rating: { type: 'number', indexed: true },
      tags: { type: 'array', indexed: true },
      images: { type: 'array' },
      specifications: { type: 'object' },
      created_at: { type: 'number', indexed: true },
    },
    indexes: [
      { name: 'unique_sku', fields: ['sku'], unique: true, type: 'unique' },
      { name: 'by_category', fields: ['category'], unique: false, type: 'hash' },
      { name: 'by_price', fields: ['price'], unique: false, type: 'range' },
      { name: 'by_rating', fields: ['rating'], unique: false, type: 'range' },
      { name: 'product_search', fields: ['name', 'description'], unique: false, type: 'fulltext' },
      { name: 'category_price', fields: ['category', 'price'], unique: false, type: 'compound' },
    ],
    required_fields: ['sku', 'name', 'category', 'price'],
  };

  const productsDataset: RegisterDatasetRequest = {
    dataset_id: 'products',
    name: 'Product Catalog',
    dataset_path: ['collections'],
    schema: productsSchema,
    owner_did: did,
    writers: [did],
    readers: [],
  };

  try {
    const dataset = await client.registerDataset(productsDataset);
    console.log('   Products dataset created');
    console.log(`   Dataset ID: ${dataset.dataset_id}`);
    console.log(`   Indexes:    ${productsSchema.indexes?.length ?? 0}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 2. Orders dataset (private)
  console.log('2. Registering "orders" dataset (private)...');
  const ordersSchema: SchemaDefinition = {
    version: 1,
    fields: {
      order_id: { type: 'string', indexed: true, required: true },
      customer_did: { type: 'string', indexed: true, required: true },
      items: { type: 'array', required: true },
      total: { type: 'number', indexed: true, required: true },
      status: { type: 'string', indexed: true, required: true },
      shipping_address: { type: 'object' },
      created_at: { type: 'number', indexed: true },
      updated_at: { type: 'number', indexed: true },
    },
    indexes: [
      { name: 'unique_order_id', fields: ['order_id'], unique: true, type: 'unique' },
      { name: 'by_customer', fields: ['customer_did'], unique: false, type: 'hash' },
      { name: 'by_status', fields: ['status'], unique: false, type: 'hash' },
      { name: 'by_date', fields: ['created_at'], unique: false, type: 'range' },
    ],
    required_fields: ['order_id', 'customer_did', 'items', 'total', 'status'],
  };

  const ordersDataset: RegisterDatasetRequest = {
    dataset_id: 'orders',
    name: 'Customer Orders',
    dataset_path: ['collections'],
    schema: ordersSchema,
    owner_did: did,
    writers: [did],
    readers: [did],
  };

  try {
    const dataset = await client.registerDataset(ordersDataset);
    console.log('   Orders dataset created');
    console.log(`   Dataset ID: ${dataset.dataset_id}`);
    console.log('   Access: private (owner only)\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 3. Users dataset (public read)
  console.log('3. Registering "users" dataset (public profiles)...');
  const usersSchema: SchemaDefinition = {
    version: 1,
    fields: {
      user_did: { type: 'string', indexed: true, required: true },
      username: { type: 'string', indexed: true, required: true },
      display_name: { type: 'string', indexed: true },
      bio: { type: 'string' },
      avatar_url: { type: 'string' },
      joined_at: { type: 'number', indexed: true },
      reputation: { type: 'number', indexed: true },
    },
    indexes: [
      { name: 'unique_did', fields: ['user_did'], unique: true, type: 'unique' },
      { name: 'unique_username', fields: ['username'], unique: true, type: 'unique' },
      { name: 'by_reputation', fields: ['reputation'], unique: false, type: 'range' },
    ],
    required_fields: ['user_did', 'username'],
  };

  const usersDataset: RegisterDatasetRequest = {
    dataset_id: 'users',
    name: 'User Profiles',
    dataset_path: ['collections'],
    schema: usersSchema,
    owner_did: did,
    writers: [did],
    readers: [],
  };

  try {
    const dataset = await client.registerDataset(usersDataset);
    console.log('   Users dataset created');
    console.log(`   Dataset ID: ${dataset.dataset_id}`);
    console.log('   Access: public read, owner write\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('Summary');
  console.log('=======');
  console.log('  - products: public catalog with full-text + range indexing');
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
