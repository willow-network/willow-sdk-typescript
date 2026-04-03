/**
 * Willow TypeScript SDK - Quickstart Example
 *
 * This example demonstrates the core workflow:
 * 1. Create a client
 * 2. Generate a DID (identity)
 * 3. Register the DID
 * 4. Authenticate
 * 5. Store and retrieve data with automatic proof verification
 *
 * Prerequisites:
 * - npm install @willow/sdk
 * - Run a local Willow node: ./scripts/start_node.sh
 *
 * Run with: npx ts-node examples/quickstart.ts
 */

import {
  WillowClient,
  generateEd25519KeyPair,
  getEd25519PublicKey,
} from '../src';

async function main() {
  console.log('Willow SDK - Quickstart Example');
  console.log('================================\n');

  // 1. Create client
  console.log('1. Creating client...');
  const client = new WillowClient({
    apiUrl: 'http://localhost:3031',
  });
  console.log('   Connected to Willow node\n');

  // 2. Generate a new DID
  console.log('2. Generating Ed25519 key pair...');
  const { privateKey, publicKey } = generateEd25519KeyPair();
  console.log(`   Private key: ${privateKey.substring(0, 16)}...`);
  console.log(`   Public key: ${publicKey.substring(0, 16)}...\n`);

  // 3. Create DID document
  console.log('3. Creating DID document...');
  const timestamp = Date.now();
  const did = `did:willow:quickstart_${timestamp}`;
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
  console.log(`   DID: ${did}\n`);

  // 4. Register the DID
  console.log('4. Registering DID...');
  try {
    await client.registerDid(didDocument);
    console.log('   DID registered successfully\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 5. Authenticate
  console.log('5. Authenticating...');
  try {
    await client.auth.login(did, privateKey, publicKeyId);
    const session = client.getSession();
    console.log(`   Authenticated successfully`);
    console.log(`   Session expires: ${new Date(session!.expires_at * 1000).toISOString()}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // For the following steps, we'll use test values
  // In production, you'd register your own subgrove first
  
  const datasetId = 'users';

  // 6. Store data
  console.log('6. Storing data...');
  const testData = {
    name: 'Alice',
    email: 'alice@example.com',
    score: 100,
    created: Date.now(),
  };

  try {
    await client.store(datasetId, 'user-1', testData);
    console.log('   Data stored successfully');
    console.log(`   Key: user-1`);
    console.log(`   Value: ${JSON.stringify(testData)}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 7. Retrieve data with automatic proof verification
  console.log('7. Retrieving data (with proof verification)...');
  try {
    const result = await client.get(datasetId, 'user-1');
    console.log('   Data retrieved and VERIFIED:');
    console.log(`   ${JSON.stringify(result.data, null, 2)}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 8. Retrieve data without verification (faster)
  console.log('8. Retrieving data (without verification)...');
  try {
    const result = await client.getUnverified(datasetId, 'user-1');
    console.log('   Data retrieved (unverified):');
    console.log(`   ${JSON.stringify(result.data, null, 2)}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 9. Update data
  console.log('9. Updating data...');
  try {
    await client.update(datasetId, 'user-1', {
      ...testData,
      score: 150,
      updated: Date.now(),
    });
    console.log('   Data updated successfully\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 10. Get root hash
  console.log('10. Getting root hash...');
  try {
    const rootHash = await client.getRootHash();
    console.log(`   Verified root hash: ${rootHash.substring(0, 32)}...\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // Summary
  console.log('Quickstart Summary');
  console.log('==================');
  console.log('- Generated Ed25519 key pair');
  console.log('- Created and registered DID');
  console.log('- Authenticated with the network');
  console.log('- Stored data with cryptographic proofs');
  console.log('- Retrieved data with automatic verification');
  console.log('- All operations include Merkle proof verification by default\n');

  console.log('Quickstart example complete!');
}

// Run the example
main().catch(console.error);
