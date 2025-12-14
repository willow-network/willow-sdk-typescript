/**
 * Indexing tests for Willow TypeScript SDK
 * 
 * These tests require a running three-node network with funded DID.
 * Run: ./scripts/start_network.sh
 */

import { WillowClient } from '../src/client';
import {
  RegisterAppRequest,
  RegisterDatasetRequest,
  SchemaDefinition,
  IndexDefinition,
  QueryRequest,
  QueryResponse,
  FieldType,
} from '../src/types';
import * as fs from 'fs';
import * as path from 'path';

// Constants for the test
const PRIVATE_KEY_HEX = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
const PUBLIC_KEY_HEX = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';

// Helper to wait for transaction propagation
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Helper to read funded DID
function getFundedDID(): string {
  try {
    const didPath = path.join(__dirname, '../../../devnet/app_owner_did.txt');
    return fs.readFileSync(didPath, 'utf-8').trim();
  } catch (error) {
    throw new Error('Funded DID file not found - ensure network is running with funding');
  }
}

describe('Willow Tests', () => {
  let client1: WillowClient;
  let client2: WillowClient;
  let client3: WillowClient;
  let fundedDID: string;
  const appId = 'indexing-test-app';

  beforeAll(async () => {
    // Get funded DID
    fundedDID = getFundedDID();
    console.log('Using funded DID:', fundedDID);

    // Create clients for each node
    client1 = new WillowClient({ apiUrl: 'http://localhost:3031' });
    client2 = new WillowClient({ apiUrl: 'http://localhost:3032' });
    client3 = new WillowClient({ apiUrl: 'http://localhost:3033' });

    // Authenticate with all nodes
    await client1.authenticate(fundedDID, PRIVATE_KEY_HEX);
    await client2.authenticate(fundedDID, PRIVATE_KEY_HEX);
    await client3.authenticate(fundedDID, PRIVATE_KEY_HEX);
  });

  describe('Schema and Index Registration', () => {
    it('should register a dataset with multiple index types', async () => {
      // Define schema with various field types
      const schema: SchemaDefinition = {
        version: 1,
        fields: {
          title: { type: 'string', indexed: true, required: true },
          content: { type: 'string', indexed: true, required: true },
          author: { type: 'string', indexed: true, required: true },
          tags: { type: 'array', indexed: true },
          timestamp: { type: 'number', indexed: true, required: true },
          views: { type: 'number', indexed: true },
          metadata: { type: 'object' },
        },
        indexes: [
          {
            name: 'by_author',
            fields: ['author'],
            unique: false,
            type: 'hash',
          },
          {
            name: 'by_timestamp',
            fields: ['timestamp'],
            unique: false,
            type: 'range',
          },
          {
            name: 'unique_title',
            fields: ['title'],
            unique: true,
            type: 'unique',
          },
          {
            name: 'content_search',
            fields: ['content'],
            unique: false,
            type: 'fulltext',
          },
        ],
      };

      const datasetRequest: RegisterDatasetRequest = {
        dataset_id: 'blog_posts',
        app_id: appId,
        name: 'Blog Posts with Indexes',
        dataset_path: [],
        schema,
        owner_did: fundedDID,
        writers: [],
        readers: [],
      };

      // Register on node 1
      const registration = await client1.data.registerDataset(datasetRequest);
      expect(registration.dataset_id).toBe('blog_posts');
      expect(registration.schema.indexes).toHaveLength(4);

      // Wait for propagation
      await sleep(3000);
    });
  });

  describe('Indexed Data Storage', () => {
    const testPosts = [
      {
        key: 'post_1',
        value: {
          title: 'Introduction to TypeScript SDK',
          content: 'Learn how to use the Willow TypeScript SDK for decentralized indexing',
          author: 'alice',
          tags: ['typescript', 'sdk', 'tutorial'],
          timestamp: 1000,
          views: 150,
          metadata: { difficulty: 'beginner' },
        },
      },
      {
        key: 'post_2',
        value: {
          title: 'Advanced Indexing Patterns',
          content: 'Explore advanced indexing patterns including fulltext search and compound indexes',
          author: 'alice',
          tags: ['indexing', 'advanced', 'patterns'],
          timestamp: 2000,
          views: 300,
          metadata: { difficulty: 'advanced' },
        },
      },
      {
        key: 'post_3',
        value: {
          title: 'Building DApps with Willow',
          content: 'How to build decentralized applications using Willow indexing infrastructure',
          author: 'bob',
          tags: ['dapp', 'blockchain', 'tutorial'],
          timestamp: 1500,
          views: 225,
          metadata: { difficulty: 'intermediate' },
        },
      },
    ];

    it('should store indexed documents', async () => {
      // Store documents via batch operation
      await client1.data.batchStore(appId, 'blog_posts', testPosts);

      // Wait for indexing
      await sleep(5000);

      // Verify data was stored
      const retrieved = await client2.data.getData(appId, 'blog_posts', 'post_1');
      expect(retrieved.title).toBe('Introduction to TypeScript SDK');
      expect(retrieved.author).toBe('alice');
    });
  });

  describe('Query Operations', () => {
    it('should query by indexed field (author)', async () => {
      const query: QueryRequest = {
        filters: {
          author: 'alice',
        },
      };

      const results = await client2.data.query(appId, 'blog_posts', query);
      expect(results.documents).toHaveLength(2);
      expect(results.documents.every(doc => doc.author === 'alice')).toBe(true);
    });

    it('should perform range queries', async () => {
      const query: QueryRequest = {
        filters: {
          timestamp: {
            $gte: 1000,
            $lte: 1500,
          },
        },
      };

      const results = await client2.data.query(appId, 'blog_posts', query);
      expect(results.documents).toHaveLength(2);
      expect(results.documents.every(doc =>
        doc.timestamp >= 1000 && doc.timestamp <= 1500
      )).toBe(true);
    });

    it('should perform fulltext search', async () => {
      const query: QueryRequest = {
        search: {
          field: 'content',
          query: 'indexing',
        },
      };

      const results = await client2.data.query(appId, 'blog_posts', query);
      expect(results.documents.length).toBeGreaterThanOrEqual(2);
      expect(results.documents.some(doc =>
        doc.content.toLowerCase().includes('indexing')
      )).toBe(true);
    });

    it('should support sorting', async () => {
      const query: QueryRequest = {
        sort: {
          field: 'views',
          order: 'desc',
        },
      };

      const results = await client2.data.query(appId, 'blog_posts', query);
      expect(results.documents).toHaveLength(3);

      // Verify descending order
      for (let i = 1; i < results.documents.length; i++) {
        expect(results.documents[i - 1].views).toBeGreaterThanOrEqual(
          results.documents[i].views
        );
      }
    });

    it('should support pagination', async () => {
      // First page
      const page1Query: QueryRequest = {
        sort: { field: 'timestamp', order: 'asc' },
        limit: 2,
        offset: 0,
      };

      const page1 = await client2.data.query(appId, 'blog_posts', page1Query);
      expect(page1.documents).toHaveLength(2);
      expect(page1.limit).toBe(2);
      expect(page1.offset).toBe(0);

      // Second page
      const page2Query: QueryRequest = {
        sort: { field: 'timestamp', order: 'asc' },
        limit: 2,
        offset: 2,
      };

      const page2 = await client2.data.query(appId, 'blog_posts', page2Query);
      expect(page2.documents.length).toBeLessThanOrEqual(2);
      expect(page2.offset).toBe(2);
    });

    it('should support compound queries', async () => {
      const query: QueryRequest = {
        filters: {
          author: 'alice',
          views: { $gte: 200 },
        },
        sort: {
          field: 'timestamp',
          order: 'desc',
        },
      };

      const results = await client2.data.query(appId, 'blog_posts', query);
      expect(results.documents).toHaveLength(1);
      expect(results.documents[0].author).toBe('alice');
      expect(results.documents[0].views).toBeGreaterThanOrEqual(200);
    });
  });

  describe('Cross-Node Consistency', () => {
    it('should have consistent query results across nodes', async () => {
      const query: QueryRequest = {
        sort: { field: 'timestamp', order: 'asc' },
      };

      // Query from all nodes
      const [results1, results2, results3] = await Promise.all([
        client1.data.query(appId, 'blog_posts', query),
        client2.data.query(appId, 'blog_posts', query),
        client3.data.query(appId, 'blog_posts', query),
      ]);

      // All nodes should return the same number of documents
      expect(results1.documents.length).toBe(results2.documents.length);
      expect(results2.documents.length).toBe(results3.documents.length);

      // Documents should be in the same order
      for (let i = 0; i < results1.documents.length; i++) {
        expect(results1.documents[i].title).toBe(results2.documents[i].title);
        expect(results2.documents[i].title).toBe(results3.documents[i].title);
      }
    });
  });

  describe('Unique Constraint Enforcement', () => {
    it('should enforce unique constraints', async () => {
      const duplicatePost = {
        title: 'Introduction to TypeScript SDK', // Duplicate title
        content: 'This should fail due to unique constraint',
        author: 'charlie',
        timestamp: 3000,
        views: 50,
      };

      await expect(
        client1.data.storeData(appId, 'blog_posts', {
          post_duplicate: duplicatePost,
        })
      ).rejects.toThrow();
    });
  });
});

describe('Performance Tests', () => {
  let client: WillowClient;
  let fundedDID: string;
  const appId = 'indexing-test-app';

  beforeAll(async () => {
    fundedDID = getFundedDID();
    client = new WillowClient({ apiUrl: 'http://localhost:3031' });
    await client.authenticate(fundedDID, PRIVATE_KEY_HEX);
  });

  it('should handle bulk indexing efficiently', async () => {
    // Create a performance test dataset
    const perfSchema: SchemaDefinition = {
      version: 1,
      fields: {
        id: { type: 'string', indexed: true, required: true },
        category: { type: 'string', indexed: true, required: true },
        value: { type: 'number', indexed: true, required: true },
        description: { type: 'string' },
      },
      indexes: [
        { name: 'by_category', fields: ['category'], unique: false, type: 'hash' },
        { name: 'by_value', fields: ['value'], unique: false, type: 'range' },
      ],
    };

    const perfDataset: RegisterDatasetRequest = {
      dataset_id: 'perf_test',
      app_id: appId,
      name: 'Performance Test Dataset',
      dataset_path: [],
      schema: perfSchema,
      owner_did: fundedDID,
      writers: [],
      readers: [],
    };

    await client.data.registerDataset(perfDataset);
    await sleep(3000);

    // Generate test data
    const categories = ['electronics', 'books', 'clothing', 'food', 'toys'];
    const testData = Array.from({ length: 50 }, (_, i) => ({
      key: `item_${i}`,
      value: {
        id: `item_${i}`,
        category: categories[i % categories.length],
        value: (i * 10) % 1000,
        description: `Test item ${i}`,
      },
    }));

    // Measure bulk insert time
    const startTime = Date.now();
    await client.data.batchStore(appId, 'perf_test', testData);
    await sleep(5000); // Wait for indexing
    const insertTime = Date.now() - startTime;

    console.log(`Inserted 50 documents in ${insertTime}ms`);
    expect(insertTime).toBeLessThan(10000); // Should complete within 10 seconds

    // Test query performance
    const queryStartTime = Date.now();
    const categoryResults = await client.data.query(appId, 'perf_test', {
      filters: { category: 'electronics' },
    });
    const categoryQueryTime = Date.now() - queryStartTime;

    console.log(`Category query returned ${categoryResults.documents.length} results in ${categoryQueryTime}ms`);
    expect(categoryQueryTime).toBeLessThan(1000); // Should complete within 1 second

    // Range query performance
    const rangeStartTime = Date.now();
    const rangeResults = await client.data.query(appId, 'perf_test', {
      filters: {
        value: { $gte: 200, $lte: 500 },
      },
    });
    const rangeQueryTime = Date.now() - rangeStartTime;

    console.log(`Range query returned ${rangeResults.documents.length} results in ${rangeQueryTime}ms`);
    expect(rangeQueryTime).toBeLessThan(1000);
  });
});