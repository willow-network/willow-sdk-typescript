/**
 * Willow TypeScript SDK - Quickstart Example
 *
 * This example demonstrates the core workflow:
 * 1. Create a client
 * 2. Generate a DID (identity)
 * 3. Register the DID
 * 4. Set identity for per-request signing
 * 5. Store and retrieve data with automatic proof verification
 *
 * Prerequisites:
 * - npm install @willow-network/sdk
 * - A local Willow node with its API server on port 3031 — see the docs
 *   for node setup: https://willow.tech
 *
 * Run with: npx ts-node examples/quickstart.ts
 */

import {
  WillowClient,
  generateEd25519KeyPair,
  createDidFromPublicKey,
} from '../src';

async function main() {
  console.log('Willow SDK - Quickstart Example');
  console.log('================================\n');

  // 1. Create client and check the node is reachable
  console.log('1. Creating client...');
  const apiUrl = 'http://localhost:3031';
  const client = new WillowClient({ apiUrl });
  try {
    const rootHash = await client.getRootHashLocal();
    console.log(`   Connected to Willow node at ${apiUrl}`);
    console.log(`   Current root hash: ${rootHash.substring(0, 16)}...\n`);
  } catch (error) {
    console.error(`   Could not reach a Willow node at ${apiUrl}.`);
    console.error('   Start a local node first — see https://willow.tech');
    console.error(`   (${error})`);
    process.exit(1);
  }

  // 2. Generate a new DID
  console.log('2. Generating Ed25519 key pair...');
  const { privateKey, publicKey } = generateEd25519KeyPair();
  console.log(`   Private key: ${privateKey.substring(0, 16)}...`);
  console.log(`   Public key: ${publicKey.substring(0, 16)}...\n`);

  // 3. Derive the self-certifying DID document. The id is bound to the key
  //    (did:willow:z<base58btc(SHA3-256(prefix||pubkey))>) — it cannot be
  //    chosen, so it is stable across runs for a given key.
  console.log('3. Deriving DID document...');
  const didDocument = createDidFromPublicKey(publicKey, 'Ed25519');
  const did = didDocument.id;
  const publicKeyId = didDocument.publicKeys[0].id;
  console.log(`   DID: ${did}\n`);

  // 4. Register the DID. Because the id is derived from the key, the DID must
  //    already hold a balance: someone transfers at least the registration fee
  //    to `did` first, then the holder registers and the fee is paid from that
  //    balance. On a funded devnet this "just works"; otherwise fund it first.
  console.log('4. Registering DID (must be pre-funded)...');
  try {
    await client.registerDid(didDocument);
    console.log('   DID registered successfully\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 5. Set identity for per-request signing (synchronous — no server session).
  console.log('5. Setting identity...');
  client.auth.setIdentity(did, privateKey, publicKeyId);
  console.log('   Identity set — every write will be signed with this key\n');

  // The remaining steps target a subgrove that needs to be registered + funded
  // first; see app_registration.ts. Errors here just fall back to printing
  // a note so the example can be skimmed without a fully provisioned node.
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
    console.log(`   ${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 8. Retrieve data without verification (faster)
  console.log('8. Retrieving data (without verification)...');
  try {
    const result = await client.getUnverified(datasetId, 'user-1');
    console.log('   Data retrieved (unverified):');
    console.log(`   ${JSON.stringify(result, null, 2)}\n`);
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

  console.log('Quickstart Summary');
  console.log('==================');
  console.log('- Generated Ed25519 key pair');
  console.log('- Created and registered DID');
  console.log('- Set identity for per-request signing (no server session)');
  console.log('- Stored data with cryptographic proofs');
  console.log('- Retrieved data with automatic verification');
  console.log('- All reads include Merkle proof verification by default\n');

  console.log('Quickstart example complete!');
}

main().catch(console.error);
