/**
 * Willow TypeScript SDK - Token and Validator Operations Example
 *
 * This example demonstrates economic operations:
 * 1. Query token information
 * 2. Check DID balances
 * 3. Check app balances
 * 4. View fee schedules
 * 5. List validators
 * 6. View validator details
 * 7. View staking statistics
 *
 * Prerequisites:
 * - npm install @willow/sdk
 * - Run a local Willow node
 *
 * Run with: npx ts-node examples/token_and_validators.ts
 */

import {
  WillowClient,
  generateEd25519KeyPair,
} from '../src';

// Helper function for API calls
async function fetchApi<T>(apiUrl: string, path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`);
  if (!response.ok) {
    throw new Error(`API error: ${response.statusText}`);
  }
  const data = await response.json() as { success: boolean; data?: T; error?: string };
  if (!data.success) {
    throw new Error(data.error || 'Unknown error');
  }
  return data.data as T;
}

// Types for token and validator responses
interface TokenInfo {
  name: string;
  symbol: string;
  decimals: number;
  genesis_supply: string;
  minted_supply: string;
  max_supply: string;
  circulating_supply: string;
}

interface Balance {
  available: number;
  locked: number;
  total: number;
}

interface FeeSchedule {
  did_registration: string;
  subgrove_registration: string;
  base_tx_cost: string;
  cost_per_byte: string;
  query_fee: string;
  transfer_fee_percentage: number;
  max_tx_size_bytes: number;
  max_data_payload_bytes: number;
}

interface Validator {
  did: string;
  address: string;
  status: string;
  stake: number;
  voting_power: number;
}

interface ValidatorSet {
  total_validators: number;
  active_validators: number;
  total_staked: number;
  total_voting_power: number;
}

async function main() {
  console.log('Willow SDK - Token & Validator Operations Example');
  console.log('=================================================\n');

  const apiUrl = 'http://localhost:3031';

  // Setup: Create client and authenticate
  const client = new WillowClient({ apiUrl });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  const timestamp = Date.now();
  const did = `did:willow:token_demo_${timestamp}`;
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

  // ============ TOKEN OPERATIONS ============
  console.log('TOKEN OPERATIONS');
  console.log('================\n');

  // 1. Get Token Info
  console.log('1. Token Information');
  console.log('--------------------');
  try {
    const tokenInfo = await fetchApi<TokenInfo>(apiUrl, '/token/info');
    console.log(`   Name: ${tokenInfo.name}`);
    console.log(`   Symbol: ${tokenInfo.symbol}`);
    console.log(`   Decimals: ${tokenInfo.decimals}`);
    console.log(`   Max Supply: ${tokenInfo.max_supply || 'N/A'}`);
    console.log(`   Circulating Supply: ${tokenInfo.circulating_supply || 'N/A'}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 2. Get Account Balance
  console.log('2. Account Balance');
  console.log('------------------');
  try {
    const balance = await fetchApi<Balance>(apiUrl, `/token/balance/${encodeURIComponent(did)}`);
    console.log(`   Available: ${balance.available?.toLocaleString() || 0} WILL`);
    console.log(`   Locked: ${balance.locked?.toLocaleString() || 0} WILL`);
    console.log(`   Total: ${balance.total?.toLocaleString() || 0} WILL\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 3. Get Subgrove Balance
  console.log('3. Subgrove Balance');
  console.log('-------------------');
  const testSubgroveId = 'demo-subgrove';
  try {
    const appBalance = await fetchApi<{ balance: number }>(apiUrl, `/subgrove/${testSubgroveId}/balance`);
    console.log(`   Subgrove: ${testSubgroveId}`);
    console.log(`   Balance: ${appBalance.balance?.toLocaleString() || 0} WILL\n`);
  } catch (error) {
    console.log(`   Subgrove "${testSubgroveId}" not found or no balance\n`);
  }

  // 4. Get Fee Schedule
  console.log('4. Fee Schedule');
  console.log('---------------');
  try {
    const fees = await fetchApi<FeeSchedule>(apiUrl, '/token/fees');
    console.log(`   Base TX Cost: ${fees.base_tx_cost || 'N/A'} wei`);
    console.log(`   Cost Per Byte: ${fees.cost_per_byte || 'N/A'} wei`);
    console.log(`   Query Fee: ${fees.query_fee || 'N/A'} wei`);
    console.log(`   Transfer Fee: ${fees.transfer_fee_percentage || 'N/A'} bps`);
    console.log(`   Max TX Size: ${fees.max_tx_size_bytes || 'N/A'} bytes`);
    console.log(`   Max Data Payload: ${fees.max_data_payload_bytes || 'N/A'} bytes\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // ============ VALIDATOR OPERATIONS ============
  console.log('VALIDATOR OPERATIONS');
  console.log('====================\n');

  // 5. List Validators
  console.log('5. List Validators');
  console.log('------------------');
  let validators: Validator[] = [];
  try {
    validators = await fetchApi<Validator[]>(apiUrl, '/validators');
    console.log(`   Total validators: ${validators.length}`);

    if (validators.length > 0) {
      console.log('\n   Top validators:');
      validators.slice(0, 5).forEach((v, i) => {
        const displayId = v.did?.substring(0, 20) || v.address?.substring(0, 20) || 'Unknown';
        console.log(`   ${i + 1}. ${displayId}...`);
        console.log(`      Status: ${v.status}`);
        console.log(`      Stake: ${v.stake?.toLocaleString() || 0} WILL`);
        console.log(`      Voting Power: ${v.voting_power || 0}%`);
      });
    }
    console.log();
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  // 6. Get Specific Validator
  console.log('6. Validator Details');
  console.log('--------------------');
  if (validators.length > 0) {
    const validatorId = validators[0].did || validators[0].address;
    try {
      const validator = await fetchApi<Validator>(
        apiUrl,
        `/validators/${encodeURIComponent(validatorId)}`
      );
      console.log(`   DID: ${validator.did || 'N/A'}`);
      console.log(`   Address: ${validator.address || 'N/A'}`);
      console.log(`   Status: ${validator.status}`);
      console.log(`   Stake: ${validator.stake?.toLocaleString() || 0} WILL`);
      console.log(`   Voting Power: ${validator.voting_power || 0}%\n`);
    } catch (error) {
      console.log(`   Note: ${error}\n`);
    }
  } else {
    console.log('   No validators available to query\n');
  }

  // 7. Get Validator Set Summary
  console.log('7. Validator Set Summary');
  console.log('------------------------');
  try {
    const validatorSet = await fetchApi<ValidatorSet>(apiUrl, '/validators/set');
    console.log(`   Total Validators: ${validatorSet.total_validators}`);
    console.log(`   Active Validators: ${validatorSet.active_validators}`);
    console.log(`   Total Staked: ${validatorSet.total_staked?.toLocaleString() || 0} WILL`);
    console.log(`   Total Voting Power: ${validatorSet.total_voting_power || 0}\n`);
  } catch (error) {
    // Try calculating from validators list
    if (validators.length > 0) {
      const activeCount = validators.filter((v) => v.status === 'active').length;
      const totalStaked = validators.reduce((sum, v) => sum + (v.stake || 0), 0);
      console.log(`   Total Validators: ${validators.length}`);
      console.log(`   Active Validators: ${activeCount}`);
      console.log(`   Total Staked: ${totalStaked.toLocaleString()} WILL\n`);
    } else {
      console.log(`   Note: ${error}\n`);
    }
  }

  // 8. Get Total Staked
  console.log('8. Staking Statistics');
  console.log('---------------------');
  try {
    const stakingStats = await fetchApi<{ total_staked: number }>(apiUrl, '/validators/staked');
    console.log(`   Total Staked: ${stakingStats.total_staked?.toLocaleString() || 0} WILL\n`);
  } catch (error) {
    // Calculate from validators if endpoint doesn't exist
    if (validators.length > 0) {
      const totalStaked = validators.reduce((sum, v) => sum + (v.stake || 0), 0);
      console.log(`   Total Staked: ${totalStaked.toLocaleString()} WILL (calculated)\n`);
    } else {
      console.log(`   Note: ${error}\n`);
    }
  }

  // Summary
  console.log('ECONOMIC MODEL SUMMARY');
  console.log('======================');
  console.log('- WILL token for storage fees and staking');
  console.log('- Pay-per-storage model (automatic deduction from subgrove balance)');
  console.log('- Validators secure the network via Proof of Stake');
  console.log('- Indexers earn rewards for indexing work');
  console.log('- Subgroves fund storage to enable data operations\n');

  console.log('Token and validator operations example complete!');
}

// Run the example
main().catch(console.error);
