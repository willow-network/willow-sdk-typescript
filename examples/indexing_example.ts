/**
 * Willow TypeScript SDK - Indexing Example
 *
 * Demonstrates:
 * 1. Defining schemas with multiple index types
 * 2. Storing indexed data
 * 3. Querying via the various index types
 *
 * Prerequisites:
 * - Run a local Willow node
 * - The funded DID env var (WILLOW_TEST_DID) needs to point at a DID
 *   that already has tokens to register a subgrove. See `app_registration.ts`
 *   for how to register one from scratch.
 */

import { WillowClient } from '../src/client';
import {
  RegisterSubgroveRequest,
  SchemaDefinition,
  QueryRequest,
} from '../src/types';

// RFC 8032 §7.1 Test 2 Ed25519 vector. In production, load from secure storage.
const PRIVATE_KEY = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';

async function main() {
  const client = new WillowClient({ apiUrl: 'http://localhost:3031' });

  // The funded DID must exist and have its public key registered. The SDK
  // can fetch the key id from the DID document via client.init():
  const fundedDID = process.env.WILLOW_TEST_DID || 'did:willow:test-owner';
  client.auth.setIdentity(fundedDID, PRIVATE_KEY, `${fundedDID}#key-1`);

  const schema: SchemaDefinition = {
    version: 1,
    fields: {
      productId: { type: 'string', indexed: true, required: true },
      category: { type: 'string', indexed: true, required: true },
      brand: { type: 'string', indexed: true },
      price: { type: 'number', indexed: true, required: true },
      stock: { type: 'number', indexed: true },
      rating: { type: 'number', indexed: true },
      name: { type: 'string', indexed: true, required: true },
      description: { type: 'string', indexed: true },
      images: { type: 'array' },
      specifications: { type: 'object' },
    },
    indexes: [
      { name: 'unique_product_id', fields: ['productId'], unique: true, type: 'unique' },
      { name: 'by_category', fields: ['category'], unique: false, type: 'hash' },
      { name: 'by_brand', fields: ['brand'], unique: false, type: 'hash' },
      { name: 'by_price', fields: ['price'], unique: false, type: 'range' },
      { name: 'product_search', fields: ['name', 'description'], unique: false, type: 'fulltext' },
      { name: 'category_price', fields: ['category', 'price'], unique: false, type: 'compound' },
    ],
  };

  const datasetRequest: RegisterSubgroveRequest = {
    dataset_id: 'products',
    name: 'Product Catalog',
    schema,
    owner_did: fundedDID,
    writers: [fundedDID],
    readers: [],
  };

  console.log('Registering product catalog dataset...');
  await client.registerSubgrove(datasetRequest);

  const products = [
    {
      key: 'prod_001',
      value: {
        productId: 'LAPTOP-001',
        name: 'UltraBook Pro 15',
        description: 'High-performance laptop with 15-inch display and latest processor',
        category: 'electronics',
        brand: 'TechCorp',
        price: 1299.99,
        stock: 50,
        rating: 4.5,
        images: ['laptop1.jpg', 'laptop2.jpg'],
        specifications: { cpu: 'Intel i7', ram: '16GB', storage: '512GB SSD' },
      },
    },
    {
      key: 'prod_002',
      value: {
        productId: 'PHONE-001',
        name: 'SmartPhone X',
        description: 'Latest smartphone with advanced camera and 5G connectivity',
        category: 'electronics',
        brand: 'PhoneMaker',
        price: 899.99,
        stock: 100,
        rating: 4.7,
        images: ['phone1.jpg', 'phone2.jpg'],
        specifications: { screen: '6.5 inch OLED', camera: '108MP', battery: '5000mAh' },
      },
    },
    {
      key: 'prod_003',
      value: {
        productId: 'BOOK-001',
        name: 'Programming Patterns',
        description: 'Comprehensive guide to design patterns and best practices',
        category: 'books',
        brand: 'TechBooks',
        price: 49.99,
        stock: 200,
        rating: 4.9,
        images: ['book1.jpg'],
        specifications: { pages: 450, format: 'Hardcover', isbn: '978-1234567890' },
      },
    },
  ];

  console.log('Storing products...');
  await client.data.batchStore('products', products);

  await new Promise((resolve) => setTimeout(resolve, 3000));

  // 1. Hash-index lookup
  console.log('\n1. Products in electronics category:');
  const electronicsResults = await client.data.query('products', {
    filters: { category: 'electronics' },
  } as QueryRequest);
  console.log(`Found ${electronicsResults.documents.length} electronics products`);

  // 1b. Query with cryptographic proof
  console.log('\n1b. Query with cryptographic proof:');
  const proofResults = await client.data.query('products', {
    filters: { category: 'electronics' },
    include_proof: true,
  } as QueryRequest);

  if (proofResults.proof && proofResults.verifiedRootHash) {
    console.log(`Proof: ${proofResults.proof.length / 2} bytes`);
    console.log(`Verified root: ${proofResults.verifiedRootHash.substring(0, 16)}...`);
  } else {
    console.log('No proof included in response');
  }

  // 2. Range index
  console.log('\n2. Products between $500-$1000:');
  const priceResults = await client.data.query('products', {
    filters: { price: { $gte: 500, $lte: 1000 } },
  } as QueryRequest);
  priceResults.documents.forEach((doc) => {
    console.log(`- ${doc.name}: $${doc.price}`);
  });

  // 3. Fulltext search
  console.log('\n3. Search for "laptop":');
  const searchResults = await client.data.query('products', {
    search: { field: 'description', query: 'laptop' },
  } as QueryRequest);
  searchResults.documents.forEach((doc) => {
    console.log(`- ${doc.name}: ${doc.description.substring(0, 50)}...`);
  });

  // 4. Compound query with sorting
  console.log('\n4. Electronics under $1500, sorted by price:');
  const compoundResults = await client.data.query('products', {
    filters: { category: 'electronics', price: { $lt: 1500 } },
    sort: { field: 'price', order: 'asc' },
  } as QueryRequest);
  compoundResults.documents.forEach((doc) => {
    console.log(`- ${doc.name}: $${doc.price}`);
  });

  // 5. Top-rated with pagination
  console.log('\n5. Top-rated products (page 1):');
  const topRatedResults = await client.data.query('products', {
    filters: { rating: { $gte: 4.0 } },
    sort: { field: 'rating', order: 'desc' },
    limit: 2,
    offset: 0,
  } as QueryRequest);
  topRatedResults.documents.forEach((doc) => {
    console.log(`- ${doc.name}: ${doc.rating}`);
  });

  console.log('\nIndexing example completed!');
}

main().catch(console.error);
