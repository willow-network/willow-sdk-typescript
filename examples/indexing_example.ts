/**
 * Example: Using Willow TypeScript SDK for Indexing
 * 
 * This example demonstrates how to:
 * 1. Define schemas with indexes
 * 2. Store indexed data
 * 3. Query using various index types
 * 
 * Prerequisites:
 * - Run the three-node network: ./scripts/start_node.sh
 */

import { WillowClient } from '../src/client';
import {
  RegisterDatasetRequest,
  SchemaDefinition,
  QueryRequest,
} from '../src/types';

// RFC 8032 §7.1 Test 2 Ed25519 vector. In production, load from secure storage.
const PRIVATE_KEY = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';

async function main() {
  // Create client
  const client = new WillowClient({
    apiUrl: 'http://localhost:3031',
  });

  // Authenticate (assuming DID is already registered and funded)
  const fundedDID = process.env.WILLOW_TEST_DID || 'did:willow:test-owner'; // Replace with actual funded DID
  await client.authenticate(fundedDID, PRIVATE_KEY);

  // Define schema with multiple index types
  const schema: SchemaDefinition = {
    version: 1,
    fields: {
      // Unique index - ensures no duplicate product IDs
      productId: { type: 'string', indexed: true, required: true },

      // Hash index - fast equality lookups
      category: { type: 'string', indexed: true, required: true },
      brand: { type: 'string', indexed: true },

      // Range index - efficient for numeric comparisons
      price: { type: 'number', indexed: true, required: true },
      stock: { type: 'number', indexed: true },
      rating: { type: 'number', indexed: true },

      // Fulltext index - for searching descriptions
      name: { type: 'string', indexed: true, required: true },
      description: { type: 'string', indexed: true },

      // Non-indexed fields
      images: { type: 'array' },
      specifications: { type: 'object' },
    },
    indexes: [
      // Unique constraint on product ID
      {
        name: 'unique_product_id',
        fields: ['productId'],
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
      {
        name: 'by_brand',
        fields: ['brand'],
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
  };

  // Register the dataset
  const datasetRequest: RegisterDatasetRequest = {
    dataset_id: 'products',
    
    name: 'Product Catalog',
    dataset_path: [],
    schema,
    owner_did: fundedDID,
    writers: [fundedDID],
    readers: [], // Public read access
  };

  console.log('Registering product catalog dataset...');
  await client.data.registerDataset(datasetRequest);

  // Store some sample products
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
        specifications: {
          cpu: 'Intel i7',
          ram: '16GB',
          storage: '512GB SSD',
        },
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
        specifications: {
          screen: '6.5 inch OLED',
          camera: '108MP',
          battery: '5000mAh',
        },
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
        specifications: {
          pages: 450,
          format: 'Hardcover',
          isbn: '978-1234567890',
        },
      },
    },
  ];

  console.log('Storing products...');
  await client.data.batchStore('products', products);

  // Wait for indexing
  await new Promise(resolve => setTimeout(resolve, 3000));

  // Example queries using different index types

  // 1. Query by category (hash index)
  console.log('\n1. Products in electronics category:');
  const electronicsQuery: QueryRequest = {
    filters: {
      category: 'electronics',
    },
  };
  const electronicsResults = await client.data.query('products', electronicsQuery);
  console.log(`Found ${electronicsResults.documents.length} electronics products`);

  // 1b. Query with cryptographic proof
  console.log('\n1b. Query with cryptographic proof:');
  const queryWithProof: QueryRequest = {
    filters: {
      category: 'electronics',
    },
    include_proof: true,
  };
  const proofResults = await client.data.query('products', queryWithProof);

  if (proofResults.proof && proofResults.root_hash) {
    console.log(`Proof included: ${proofResults.proof.length / 2} bytes`);
    console.log(`Root hash: ${proofResults.root_hash.substring(0, 16)}...`);

    // Verify the proof
    const { verifyQueryResponse } = await import('../src/proof');
    const verificationResult = await verifyQueryResponse(proofResults);

    if (verificationResult.valid) {
      console.log('✅ Proof verification passed!');
    } else {
      console.log('❌ Proof verification failed:', verificationResult.error);
    }
  } else {
    console.log('⚠️  No proof included in response');
  }

  // 2. Price range query (range index)
  console.log('\n2. Products between $500-$1000:');
  const priceRangeQuery: QueryRequest = {
    filters: {
      price: {
        $gte: 500,
        $lte: 1000,
      },
    },
  };
  const priceResults = await client.data.query('products', priceRangeQuery);
  priceResults.documents.forEach(doc => {
    console.log(`- ${doc.name}: $${doc.price}`);
  });

  // 3. Fulltext search
  console.log('\n3. Search for "laptop":');
  const searchQuery: QueryRequest = {
    search: {
      field: 'description',
      query: 'laptop',
    },
  };
  const searchResults = await client.data.query('products', searchQuery);
  searchResults.documents.forEach(doc => {
    console.log(`- ${doc.name}: ${doc.description.substring(0, 50)}...`);
  });

  // 4. Compound query with sorting
  console.log('\n4. Electronics under $1500, sorted by price:');
  const compoundQuery: QueryRequest = {
    filters: {
      category: 'electronics',
      price: { $lt: 1500 },
    },
    sort: {
      field: 'price',
      order: 'asc',
    },
  };
  const compoundResults = await client.data.query('products', compoundQuery);
  compoundResults.documents.forEach(doc => {
    console.log(`- ${doc.name}: $${doc.price}`);
  });

  // 5. Top-rated products with pagination
  console.log('\n5. Top-rated products (page 1):');
  const topRatedQuery: QueryRequest = {
    filters: {
      rating: { $gte: 4.0 },
    },
    sort: {
      field: 'rating',
      order: 'desc',
    },
    limit: 2,
    offset: 0,
  };
  const topRatedResults = await client.data.query('products', topRatedQuery);
  topRatedResults.documents.forEach(doc => {
    console.log(`- ${doc.name}: ⭐ ${doc.rating}`);
  });

  console.log('\nIndexing example completed!');
}

// Run the example
main().catch(console.error);