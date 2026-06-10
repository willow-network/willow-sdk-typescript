/**
 * Willow TypeScript SDK - Light Client Example (experimental)
 *
 * Demonstrates the CometBFT light client API:
 * 1. Configure the light client (test/mainnet/custom)
 * 2. Start the client + sync to latest
 * 3. Verify a query proof against the trusted state
 * 4. Export/import trusted headers for persistence
 *
 * Current trust model: the root-hash path reads app_hash from the
 * configured RPC endpoint(s) and trusts the response — commit-signature
 * verification is not wired in yet (see the LightClient class docs).
 *
 * Prerequisites:
 * - npm install @willow-network/sdk
 * - A local Willow network with multiple validators — see the node repo
 *   for setup: https://github.com/willow-network/willow
 *
 * Run with: npx ts-node examples/light_client.ts
 */

import {
  LightClient,
  LightClientConfigBuilder,
  lightClientTestConfig,
  lightClientMainnetConfig,
} from '../src';

async function main() {
  console.log('Willow SDK - Light Client Example');
  console.log('==================================\n');

  // 1. Configuration
  console.log('1. Light Client Configuration');
  console.log('-----------------------------\n');

  console.log('   1a. Test configuration (local development):');
  const testConfig = lightClientTestConfig('test-chain-consensus').build();
  console.log(`       Chain ID:    ${testConfig.chainId}`);
  console.log(`       Validators:  ${testConfig.validatorEndpoints.length}`);
  console.log(`       Threshold:   2/3`);
  console.log(`       Trusting period: 24 hours\n`);

  console.log('   1b. Mainnet configuration:');
  const mainnetConfig = lightClientMainnetConfig('willow-mainnet')
    .validatorEndpoints([
      'https://validator1.example.com:26657',
      'https://validator2.example.com:26657',
      'https://validator3.example.com:26657',
    ])
    .build();
  console.log(`       Chain ID:    ${mainnetConfig.chainId}`);
  console.log(`       Threshold:   2/3`);
  console.log(`       Trusting period: 14 days\n`);

  console.log('   1c. Custom configuration:');
  const customConfig = new LightClientConfigBuilder('custom-chain')
    .validatorEndpoints([
      'http://localhost:26657',
      'http://localhost:26757',
      'http://localhost:26857',
    ])
    .trustThreshold(2, 3)
    .trustingPeriodDays(7)
    .maxClockDriftSecs(10)
    .minValidatorsForConsensus(2)
    .autoSync(true)
    .syncIntervalMinutes(5)
    .maxRetries(3)
    .requestTimeoutSecs(30)
    .build();
  console.log(`       Chain ID:    ${customConfig.chainId}`);
  console.log(`       Auto sync:   ${customConfig.autoSync}`);
  console.log(`       Sync every:  ${customConfig.syncIntervalSecs}s\n`);

  // 2. Create + start
  console.log('2. Creating and starting the light client');
  console.log('-----------------------------------------');

  const lightClient = new LightClient(testConfig);
  try {
    await lightClient.start();
    console.log('   Light client started\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 3. Sync
  console.log('3. Header synchronization');
  console.log('-------------------------');
  try {
    const syncResult = await lightClient.syncToLatest();
    if (syncResult.success) {
      console.log(`   Synced to height: ${syncResult.height}`);
    } else {
      console.log(`   Sync note: ${syncResult.error}`);
    }
  } catch (error) {
    console.log(`   Note: ${error}`);
  }

  try {
    const latestHeader = await lightClient.getLatestHeader();
    if (latestHeader) {
      console.log(`   Latest verified height: ${latestHeader.header.height}`);
      console.log(`   Chain ID:               ${latestHeader.header.chainId}`);
    }
  } catch (error) {
    console.log(`   Note: ${error}`);
  }

  try {
    const range = await lightClient.getVerifiedHeightRange();
    if (range) {
      console.log(`   Verified range: ${range[0]} - ${range[1]}`);
    }
  } catch (error) {
    console.log(`   Note: ${error}`);
  }
  console.log();

  // 4. Proof verification
  console.log('4. Proof Verification');
  console.log('---------------------');
  console.log('   When you call client.get() or client.query(), the SDK:');
  console.log('   - Fetches the data + proof from the API');
  console.log('   - Retrieves the trusted header for the proof height');
  console.log('   - Verifies the proof against the header app_hash');
  console.log('   - Throws if verification fails');
  console.log();
  console.log('   To verify manually:');
  console.log('     const result = await lightClient.verifyQueryProof(proof);');
  console.log('     if (result.success) { /* data is verified */ }\n');

  // 5. State persistence
  console.log('5. State Persistence');
  console.log('--------------------');
  console.log('   Export trusted headers and persist them so you can resume');
  console.log('   without re-syncing from scratch.\n');

  try {
    const trustedState = await lightClient.exportTrustedState();
    console.log(`   Exported ${trustedState.length} trusted headers`);
    if (trustedState.length > 0) {
      console.log(`   First header height: ${trustedState[0].header.height}`);
    }
    // In a browser:
    //   localStorage.setItem('willow_trusted_state', JSON.stringify(trustedState));
    // On Node:
    //   fs.writeFileSync('trusted_state.json', JSON.stringify(trustedState));
    console.log('   (persist trustedState via localStorage / IndexedDB / file)\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('   Restore on next run:');
  console.log('     await lightClient.importTrustedState(savedHeaders);');
  console.log('     // resumes verification without re-syncing\n');

  // 6. Integration with WillowClient
  console.log('6. Integration with WillowClient');
  console.log('--------------------------------');
  console.log('   The WillowClient instance auto-creates a light client on its');
  console.log('   first proof-verified read (trust-on-first-use). For full control');
  console.log('   you can construct one explicitly as shown above and call its');
  console.log('   methods directly; the embedded one is reachable via');
  console.log('   client.data.getOrCreateLightClient() (internal).\n');

  // 7. Stop
  console.log('7. Stopping the light client');
  console.log('----------------------------');
  try {
    await lightClient.stop();
    console.log('   Light client stopped\n');
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('LIGHT CLIENT SUMMARY');
  console.log('====================');
  console.log('- Verifies GroveDB Merkle proofs against the fetched app_hash');
  console.log('- EXPERIMENTAL: the root-hash path trusts the configured RPC');
  console.log('  endpoints; commit-signature verification is not wired in yet');
  console.log('- Trusting period limits exposure to long-range attacks');
  console.log('- Trusted state can be exported/imported across runs');
  console.log();

  console.log('Light client example complete!');
}

main().catch(console.error);
