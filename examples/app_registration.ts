/**
 * Willow TypeScript SDK - App Registration Example
 *
 * This example demonstrates how to:
 * 1. Register an application
 * 2. Create datasets (subgroves) with schemas
 * 3. Define indexes for efficient queries
 * 4. Manage permissions
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
  RegisterAppRequest,
  RegisterDatasetRequest,
  SchemaDefinition,
} from '../src';

async function main() {
  console.log('Willow SDK - App Registration Example');
  console.log('=====================================\n');

  // Setup: Create client and authenticate
  const client = new WillowClient({
    apiUrl: 'http://localhost:3031',
  });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  const timestamp = Date.now();
  const did = `did:willow:app_owner_${timestamp}`;
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

  // 1. Register an Application
  console.log('1. Registering application...');
  const appId = `ecommerce-app-${timestamp}`;

  const appRequest: RegisterAppRequest = {
    app_id: appId,
    name: 'E-Commerce Platform',
    description: 'A decentralized e-commerce application with verified data',
    app_type: 'web',
    owner_did: did,
    admins: [], // Additional admin DIDs can be added here
  };

  try {
    const app = await client.registerApp(appRequest);
    console.log('   Application registered successfully');
    console.log(`   App ID: ${app.app_id}`);
    console.log(`   Name: ${app.name}`);
    console.log(`   Owner: ${app.owner_did}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 2. Create Products Dataset with Schema
  console.log('2. Creating products dataset...');

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
      // Unique constraint on SKU
      {
        name: 'unique_sku',
        fields: ['sku'],
        unique: true,
        type: 'unique',
      },
      // Hash indexes for exact matches
      {
        name: 'by_category',
        fields: ['category'],
        unique: false,
        type: 'hash',
      },
      // Range indexes for numeric queries
      {
        name: 'by_price',
        fields: ['price'],
        unique: false,
        type: 'range',
      },
      {
        name: 'by_rating',
        fields: ['rating'],
        unique: false,
        type: 'range',
      },
      // Fulltext index for search
      {
        name: 'product_search',
        fields: ['name', 'description'],
        unique: false,
        type: 'fulltext',
      },
      // Compound index for category + price range queries
      {
        name: 'category_price',
        fields: ['category', 'price'],
        unique: false,
        type: 'compound',
      },
    ],
    required_fields: ['sku', 'name', 'category', 'price'],
  };

  const productsDataset: RegisterDatasetRequest = {
    dataset_id: 'products',
    app_id: appId,
    name: 'Product Catalog',
    dataset_path: ['collections'],
    schema: productsSchema,
    owner_did: did,
    writers: [did],
    readers: [], // Public read access
  };

  try {
    const dataset = await client.registerDataset(productsDataset);
    console.log('   Products dataset created');
    console.log(`   Dataset ID: ${dataset.dataset_id}`);
    console.log(`   Indexes: ${productsSchema.indexes?.length || 0}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 3. Create Orders Dataset
  console.log('3. Creating orders dataset...');

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
      {
        name: 'unique_order_id',
        fields: ['order_id'],
        unique: true,
        type: 'unique',
      },
      {
        name: 'by_customer',
        fields: ['customer_did'],
        unique: false,
        type: 'hash',
      },
      {
        name: 'by_status',
        fields: ['status'],
        unique: false,
        type: 'hash',
      },
      {
        name: 'by_date',
        fields: ['created_at'],
        unique: false,
        type: 'range',
      },
    ],
    required_fields: ['order_id', 'customer_did', 'items', 'total', 'status'],
  };

  const ordersDataset: RegisterDatasetRequest = {
    dataset_id: 'orders',
    app_id: appId,
    name: 'Customer Orders',
    dataset_path: ['collections'],
    schema: ordersSchema,
    owner_did: did,
    writers: [did], // Only owner can write orders
    readers: [did], // Only owner can read orders (private)
  };

  try {
    const dataset = await client.registerDataset(ordersDataset);
    console.log('   Orders dataset created');
    console.log(`   Dataset ID: ${dataset.dataset_id}`);
    console.log(`   Access: Private (owner only)\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 4. Create Users Dataset with Public Profiles
  console.log('4. Creating users dataset...');

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
      {
        name: 'unique_did',
        fields: ['user_did'],
        unique: true,
        type: 'unique',
      },
      {
        name: 'unique_username',
        fields: ['username'],
        unique: true,
        type: 'unique',
      },
      {
        name: 'by_reputation',
        fields: ['reputation'],
        unique: false,
        type: 'range',
      },
    ],
    required_fields: ['user_did', 'username'],
  };

  const usersDataset: RegisterDatasetRequest = {
    dataset_id: 'users',
    app_id: appId,
    name: 'User Profiles',
    dataset_path: ['collections'],
    schema: usersSchema,
    owner_did: did,
    writers: [did], // Admin can write
    readers: [], // Public read
  };

  try {
    const dataset = await client.registerDataset(usersDataset);
    console.log('   Users dataset created');
    console.log(`   Dataset ID: ${dataset.dataset_id}`);
    console.log(`   Access: Public read, admin write\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 5. Summary
  console.log('5. Registration Summary');
  console.log('=======================');
  console.log(`App: ${appId}`);
  console.log('Datasets:');
  console.log('  - products: Product catalog with search and filtering');
  console.log('  - orders: Private order records');
  console.log('  - users: Public user profiles\n');

  console.log('Data Organization:');
  console.log(`  ${appId}/`);
  console.log('    ├── products/');
  console.log('    │   └── (indexed product documents)');
  console.log('    ├── orders/');
  console.log('    │   └── (private order documents)');
  console.log('    └── users/');
  console.log('        └── (public profile documents)\n');

  console.log('Index Types Used:');
  console.log('  - unique: Ensures no duplicate values (SKU, order_id, username)');
  console.log('  - hash: Fast equality lookups (category, status, customer_did)');
  console.log('  - range: Efficient numeric comparisons (price, rating, date)');
  console.log('  - fulltext: Text search (name, description)');
  console.log('  - compound: Multi-field queries (category + price)\n');

  console.log('App registration example complete!');
}

// Run the example
main().catch(console.error);
