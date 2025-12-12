/**
 * Demonstration of GroveDB proof verification in TypeScript SDK
 * 
 * This example shows different ways to use proof verification:
 * 1. Default automatic verification
 * 2. Server-assisted verification
 * 3. Manual verification with expected root hash
 * 4. Extracting root hash without full verification
 */

import { WillowClient } from '../src/client';
import {
  configureProofVerification,
  verifyProofAdvanced,
  extractRootHashFromProof
} from '../src/proof';

async function main() {
  console.log('🔐 GroveDB Proof Verification Demo');
  console.log('==================================\n');

  // Example 1: Default client with automatic proof verification
  console.log('1️⃣  Default Client (Local Verification)');
  console.log('----------------------------------------');

  const client1 = new WillowClient({
    apiUrl: 'http://localhost:3031',
    did: 'did:willow:example',
    privateKey: 'your-private-key-here'
  });

  try {
    // This will automatically verify proofs using local verification
    const data = await client1.data.getData('myapp', 'users', 'user123');
    console.log('✅ Data retrieved with automatic proof verification');
    console.log('   Note: Using basic local verification (extracting root hash)');
  } catch (error) {
    console.log('❌ Verification failed:', error.message);
  }

  // Example 2: Client with server-assisted verification
  console.log('\n2️⃣  Server-Assisted Verification');
  console.log('----------------------------------');

  const client2 = new WillowClient({
    apiUrl: 'http://localhost:3031',
    did: 'did:willow:example',
    privateKey: 'your-private-key-here',
    proofVerificationOptions: {
      serverAssisted: true,
      apiUrl: 'http://localhost:3031'
    }
  });

  console.log('✅ Client configured for server-assisted verification');
  console.log('   Server will parse and verify GroveDB proofs');
  console.log('   More accurate but requires server support');

  // Example 3: Manual verification with expected root hash
  console.log('\n3️⃣  Manual Verification with Expected Root Hash');
  console.log('------------------------------------------------');

  // Get the verified root hash from consensus
  const response = await fetch('http://localhost:3031/state/root-hash/verified');
  const rootHashData = await response.json();
  const verifiedRootHash = rootHashData.data.root_hash;

  console.log(`📊 Verified root hash from consensus: ${verifiedRootHash.substring(0, 16)}...`);

  // Configure global verifier with expected root hash
  configureProofVerification({
    expectedRootHash: verifiedRootHash
  });

  // Now any proof verification will check against this root hash
  const client3 = new WillowClient({
    apiUrl: 'http://localhost:3031',
    did: 'did:willow:example',
    privateKey: 'your-private-key-here'
  });

  console.log('✅ Client will verify all proofs against consensus root hash');

  // Example 4: Advanced manual verification
  console.log('\n4️⃣  Advanced Manual Verification');
  console.log('---------------------------------');

  // Get proof manually
  const proofResponse = await fetch('http://localhost:3031/proof/myapp/users/user123');
  const proofData = await proofResponse.json();

  if (proofData.success && proofData.data?.proof) {
    const proof = proofData.data.proof;

    // Extract root hash without full verification
    try {
      const extractedHash = await extractRootHashFromProof(proof);
      console.log(`📋 Extracted root hash: ${extractedHash.substring(0, 16)}...`);

      // Compare with consensus
      if (extractedHash.toLowerCase() === verifiedRootHash.toLowerCase()) {
        console.log('✅ Root hash matches consensus!');
      } else {
        console.log('❌ Root hash mismatch!');
      }
    } catch (error) {
      console.log('❌ Failed to extract root hash:', error.message);
    }

    // Full verification with options
    const result = await verifyProofAdvanced(
      proof,
      [{ key: 'user123', value: { name: 'Test User' } }],
      {
        expectedRootHash: verifiedRootHash
      }
    );

    console.log('\n📊 Verification Result:');
    console.log(`   Valid: ${result.valid}`);
    console.log(`   Method: ${result.method}`);
    console.log(`   Root Hash: ${result.rootHash?.substring(0, 16)}...`);
    if (result.error) {
      console.log(`   Error: ${result.error}`);
    }
  }

  // Example 5: Query with proof verification
  console.log('\n5️⃣  Query with Automatic Proof Verification');
  console.log('--------------------------------------------');

  const queryResult = await client1.data.query('myapp', 'users', {
    where: { age: { gt: 18 } },
    limit: 10
  });

  console.log(`✅ Query returned ${queryResult.documents.length} results`);
  console.log('   All results are cryptographically verified');

  // The verifiedRootHash is added to the response
  if ((queryResult as any).verifiedRootHash) {
    console.log(`   Verified against root: ${(queryResult as any).verifiedRootHash.substring(0, 16)}...`);
  }

  // Example 6: Opting out of verification for performance
  console.log('\n6️⃣  Unverified Operations (Performance Mode)');
  console.log('--------------------------------------------');

  const unverifiedData = await client1.data.getDataUnverified('myapp', 'users', 'user123');
  console.log('⚡ Data retrieved without proof verification (faster)');

  const unverifiedQuery = await client1.data.queryUnverified('myapp', 'users', {
    where: { age: { gt: 18 } },
    limit: 10
  });
  console.log(`⚡ Query returned ${unverifiedQuery.documents.length} results (unverified)`);

  console.log('\n✅ Demo Complete!');
  console.log('================');
  console.log('\n💡 Key Takeaways:');
  console.log('   • TypeScript SDK now supports GroveDB proof verification');
  console.log('   • Default mode uses local verification (extracts root hash)');
  console.log('   • Server-assisted mode available for full verification');
  console.log('   • Can verify against consensus root hash');
  console.log('   • Unverified mode available for performance-critical paths');
}

// Run the demo
main().catch(console.error);