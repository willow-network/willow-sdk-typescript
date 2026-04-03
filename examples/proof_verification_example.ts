/**
 * Example demonstrating secure-by-default proof verification in TypeScript SDK
 */

import { WillowClient } from '../src';

async function main() {
  // Initialize client
  const client = new WillowClient({
    apiUrl: 'http://localhost:3031',
    did: 'did:willow:local:test-owner',
    privateKey: 'your-private-key-here'
  });

  await client.init();

  
  const datasetId = 'users';

  try {
    // 1. Secure by default - getData automatically verifies proof
    console.log('Fetching data with automatic proof verification...');
    const userData = await client.get(datasetId, 'user123');
    console.log('Data retrieved and verified:', userData);

    // 2. Query with automatic proof verification
    console.log('\nQuerying data with automatic proof verification...');
    const queryResult = await client.query(datasetId, {
      filters: { active: true },
      limit: 10
    });
    console.log('Query results verified. Document count:', queryResult.documents.length);
    if (queryResult.verifiedRootHash) {
      console.log('Verified root hash:', queryResult.verifiedRootHash);
    }

    // 3. Performance mode - skip verification when needed
    console.log('\nFetching data without verification (performance mode)...');
    const unverifiedData = await client.getUnverified(datasetId, 'user123');
    console.log('Unverified data retrieved:', unverifiedData);

    // 4. Collection helper also supports both modes
    const collection = client.collection(datasetId);

    // Secure by default
    const verifiedUser = await collection.get('user456');
    console.log('\nCollection get (verified):', verifiedUser);

    // Performance mode
    const unverifiedUser = await collection.getUnverified('user456');
    console.log('Collection get (unverified):', unverifiedUser);

    // 5. Batch operations with verification
    const multipleUsers = await collection.getMultiple(['user1', 'user2', 'user3']);
    console.log('\nBatch get (verified):', Object.keys(multipleUsers).length, 'users');

    // 6. Get root hashes for manual verification
    const verifiedRootHash = await client.getRootHash();
    const localRootHash = await client.getRootHashLocal();
    console.log('\nRoot hashes:');
    console.log('- Verified (consensus):', verifiedRootHash);
    console.log('- Local (current state):', localRootHash);

  } catch (error) {
    if (error.code === 'PROOF_VERIFICATION_FAILED') {
      console.error('Proof verification failed! Data may have been tampered with.');
    } else {
      console.error('Error:', error.message);
    }
  }
}

// Run the example
main().catch(console.error);