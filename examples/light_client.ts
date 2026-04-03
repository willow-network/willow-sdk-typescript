/**
 * Willow TypeScript SDK - Light Client Example
 *
 * This example demonstrates trustless verification using the light client:
 * 1. Configure the light client
 * 2. Initialize with a trusted header
 * 3. Sync to latest blockchain state
 * 4. Verify headers from validators
 * 5. Verify GroveDB query proofs
 * 6. Export/import trusted state for persistence
 *
 * The light client provides cryptographic security without running a full node
 * by verifying validator signatures and Merkle proofs.
 *
 * Prerequisites:
 * - npm install @willow/sdk
 * - Run a local Willow network with multiple validators
 *
 * Run with: npx ts-node examples/light_client.ts
 */

import {
  LightClient,
  LightClientConfigBuilder,
  lightClientTestConfig,
  lightClientMainnetConfig,
  lightClientFastSyncConfig,
  createTrustThreshold,
  WillowClient,
  generateEd25519KeyPair,
} from '../src';

async function main() {
  console.log('Willow SDK - Light Client Example');
  console.log('==================================\n');

  // ============ CONFIGURATION ============
  console.log('1. Light Client Configuration');
  console.log('-----------------------------\n');

  // Option 1: Use preset configuration for testing
  console.log('   1a. Test Configuration (local development):');
  const testConfigBuilder = lightClientTestConfig('test-chain-consensus');
  const testConfig = testConfigBuilder.build();
  console.log(`       Chain ID: ${testConfig.chainId}`);
  console.log(`       Validators: ${testConfig.validatorEndpoints.length}`);
  console.log(`       Trust threshold: 2/3`);
  console.log(`       Trusting period: 24 hours\n`);

  // Option 2: Use mainnet configuration
  console.log('   1b. Mainnet Configuration:');
  const mainnetConfigBuilder = lightClientMainnetConfig('willow-mainnet')
    .validatorEndpoints([
      'https://validator1.willow.network:26657',
      'https://validator2.willow.network:26657',
      'https://validator3.willow.network:26657',
    ]);
  const mainnetConfig = mainnetConfigBuilder.build();
  console.log(`       Chain ID: ${mainnetConfig.chainId}`);
  console.log(`       Trust threshold: 2/3`);
  console.log(`       Trusting period: 14 days\n`);

  // Option 3: Custom configuration
  console.log('   1c. Custom Configuration:');
  const customConfig = new LightClientConfigBuilder('custom-chain')
    .validatorEndpoints([
      'http://localhost:26657',
      'http://localhost:26757',
      'http://localhost:26857',
    ])
    .trustThreshold(2, 3) // Require 2/3+ validator signatures
    .trustingPeriodDays(7) // Headers trusted for 7 days
    .maxClockDriftSecs(10) // Allow 10 seconds clock drift
    .minValidatorsForConsensus(2) // Need 2 validators to agree
    .autoSync(true) // Automatically sync headers
    .syncIntervalMinutes(5) // Sync every 5 minutes
    .maxRetries(3)
    .requestTimeoutSecs(30)
    .build();
  console.log(`       Chain ID: ${customConfig.chainId}`);
  console.log(`       Auto sync: ${customConfig.autoSync}`);
  console.log(`       Sync interval: ${customConfig.syncIntervalSecs}s\n`);

  // ============ LIGHT CLIENT USAGE ============
  console.log('2. Creating Light Client');
  console.log('------------------------');

  // Use test config for this example
  const lightClient = new LightClient(testConfig);
  console.log('   Light client created\n');

  // Start the light client
  console.log('3. Starting Light Client');
  console.log('------------------------');
  try {
    await lightClient.start();
    console.log('   Light client started\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // ============ HEADER VERIFICATION ============
  console.log('4. Header Synchronization');
  console.log('-------------------------');

  // Sync to latest
  try {
    console.log('   Syncing to latest blockchain state...');
    const syncResult = await lightClient.syncToLatest();
    if (syncResult.success) {
      console.log(`   Synced to height: ${syncResult.height}`);
    } else {
      console.log(`   Sync note: ${syncResult.error}`);
    }
  } catch (error) {
    console.log(`   Note: ${error}`);
  }

  // Get latest verified header
  try {
    const latestHeader = await lightClient.getLatestHeader();
    if (latestHeader) {
      console.log(`   Latest verified height: ${latestHeader.header.height}`);
      console.log(`   Chain ID: ${latestHeader.header.chainId}`);
    }
  } catch (error) {
    console.log(`   Note: ${error}`);
  }

  // Get verified height range
  try {
    const range = await lightClient.getVerifiedHeightRange();
    if (range) {
      console.log(`   Verified range: ${range[0]} - ${range[1]}`);
    }
  } catch (error) {
    console.log(`   Note: ${error}`);
  }
  console.log();

  // ============ PROOF VERIFICATION ============
  console.log('5. Proof Verification');
  console.log('---------------------');
  console.log('   The light client verifies GroveDB proofs against trusted headers.\n');

  // Example: Verify a query proof
  console.log('   5a. Query Proof Verification:');
  console.log('   When you call client.get() or client.query(), the SDK:');
  console.log('   - Fetches data and proof from the API');
  console.log('   - Retrieves the trusted header for that height');
  console.log('   - Verifies the proof against the header\'s app hash');
  console.log('   - Returns error if verification fails\n');

  // Example proof structure (would come from actual query)
  const exampleProof = {
    height: 100,
    proof: new Uint8Array([/* GroveDB proof bytes */]),
    rootHash: new Uint8Array([/* Root hash bytes */]),
    key: 'example-key',
  };

  try {
    // In production, this would verify an actual proof
    // const result = await lightClient.verifyQueryProof(exampleProof);
    console.log('   To verify a proof manually:');
    console.log('   const result = await lightClient.verifyQueryProof(proof);');
    console.log('   if (result.success) { /* Data is verified */ }\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // ============ STATE PERSISTENCE ============
  console.log('6. State Persistence');
  console.log('--------------------');
  console.log('   Export trusted headers for storage and later restoration.\n');

  // Export trusted state
  console.log('   6a. Export Trusted State:');
  try {
    const trustedState = await lightClient.exportTrustedState();
    console.log(`       Exported ${trustedState.length} trusted headers`);
    if (trustedState.length > 0) {
      console.log(`       First header height: ${trustedState[0].header.height}`);
    }

    // In production, you would save this to localStorage, IndexedDB, or file
    // localStorage.setItem('willow_trusted_state', JSON.stringify(trustedState));
    console.log('       // Save to localStorage or IndexedDB\n');
  } catch (error) {
    console.log(`       Note: ${error}\n`);
  }

  // Import trusted state
  console.log('   6b. Import Trusted State:');
  console.log('       // const savedState = JSON.parse(localStorage.getItem(\'willow_trusted_state\'));');
  console.log('       // await lightClient.importTrustedState(savedState);');
  console.log('       This restores previous verification without re-syncing\n');

  // ============ USING WITH WILLOW CLIENT ============
  console.log('7. Integration with WillowClient');
  console.log('--------------------------------');
  console.log('   The light client integrates with WillowClient for automatic verification.\n');

  console.log('   Example setup:');
  console.log('   ```typescript');
  console.log('   // Create and configure light client');
  console.log('   const lightClient = new LightClient(config);');
  console.log('   await lightClient.start();');
  console.log('   await lightClient.syncToLatest();');
  console.log('');
  console.log('   // Create Willow client with proof verification');
  console.log('   const client = new WillowClient({');
  console.log('     apiUrl: \'http://localhost:3031\',');
  console.log('     proofVerificationOptions: {');
  console.log('       enabled: true,');
  console.log('       lightClient: lightClient,');
  console.log('     },');
  console.log('   });');
  console.log('');
  console.log('   // All data operations are now verified');
  console.log('   const data = await client.get(datasetId, key);');
  console.log('   // Throws if proof verification fails');
  console.log('   ```\n');

  // ============ STOP LIGHT CLIENT ============
  console.log('8. Stopping Light Client');
  console.log('------------------------');
  try {
    await lightClient.stop();
    console.log('   Light client stopped\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // ============ SUMMARY ============
  console.log('LIGHT CLIENT SUMMARY');
  console.log('====================\n');

  console.log('Security Model:');
  console.log('- Verifies 2/3+ validator signatures on block headers');
  console.log('- Verifies GroveDB Merkle proofs against app hash in headers');
  console.log('- No trust required in any single node\n');

  console.log('Trust Threshold:');
  console.log('- Default: 2/3 (Byzantine fault tolerant)');
  console.log('- Configurable based on security requirements');
  console.log('- Lower threshold = faster sync, less security\n');

  console.log('Trusting Period:');
  console.log('- Headers are trusted for a limited time');
  console.log('- Must sync periodically to maintain trust');
  console.log('- Prevents long-range attacks\n');

  console.log('State Persistence:');
  console.log('- Export trusted headers for storage');
  console.log('- Import on app restart to avoid full re-sync');
  console.log('- Reduces startup time significantly\n');

  console.log('Configuration Presets:');
  console.log('- testConfig(): Local development with 3 validators');
  console.log('- mainnetConfig(): Production with 14-day trust period');
  console.log('- fastSyncConfig(): Faster sync with relaxed security\n');

  console.log('Light client example complete!');
}

// Run the example
main().catch(console.error);
