/**
 * Willow TypeScript SDK - Token and Validator Operations Example
 *
 * Read-only economic operations using REST endpoints:
 * 1. Token information
 * 2. DID balance
 * 3. Subgrove balance
 * 4. Fee schedule
 * 5. List validators
 * 6. Validator details
 * 7. Validator set summary
 *
 * Note: The TypeScript SDK doesn't ship a token/validators class — these
 * endpoints are direct REST reads. Transfers and stakes go through the
 * ConsensusClient (client.consensus.transfer / stake), not these reads.
 *
 * Prerequisites:
 * - npm install @willow/sdk
 * - Run a local Willow node
 *
 * Run with: npx ts-node examples/token_and_validators.ts
 */

import { WillowClient, generateEd25519KeyPair } from '../src';

async function fetchApi<T>(apiUrl: string, path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`);
  if (!response.ok) throw new Error(`API error: ${response.statusText}`);
  const data = (await response.json()) as { success: boolean; data?: T; error?: string };
  if (!data.success) throw new Error(data.error || 'Unknown error');
  return data.data as T;
}

// Pydantic-mirrored shapes for the REST surface. These intentionally
// match the field names the server returns (see willow-types).
interface TokenInfo {
  name: string;
  symbol: string;
  decimals: number;
  genesis_supply: string;
  minted_supply: string;
  max_supply: string;
  circulating_supply: string;
}

interface BalanceInfo {
  account: string;
  balance: string;
  staked: string;
  unbonding: string;
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
  validator_did: string;
  name?: string;
  stake_amount: string;
  status: string;
  voting_power: number;
  consensus_pubkey?: string;
}

interface ValidatorSet {
  total_validators: number;
  active_validators: number;
  total_staked: string;
  total_voting_power: number;
}

async function main() {
  console.log('Willow SDK - Token & Validator Operations Example');
  console.log('=================================================\n');

  const apiUrl = 'http://localhost:3031';
  const client = new WillowClient({ apiUrl });

  const { privateKey, publicKey } = generateEd25519KeyPair();
  const timestamp = Date.now();
  const did = `did:willow:token_demo_${timestamp}`;
  const publicKeyId = `${did}#key-1`;
  const didDocument = {
    id: did,
    publicKeys: [{ id: publicKeyId, type: 'Ed25519', publicKeyHex: publicKey }],
    created: timestamp,
    updated: timestamp,
  };

  console.log('Setting up identity...');
  try {
    await client.registerDid(didDocument);
    client.auth.setIdentity(did, privateKey, publicKeyId);
    console.log(`Authenticated as: ${did}\n`);
  } catch (error) {
    console.log(`Note: ${error}\n`);
  }

  console.log('TOKEN OPERATIONS');
  console.log('================\n');

  console.log('1. Token Information');
  console.log('--------------------');
  try {
    const tokenInfo = await fetchApi<TokenInfo>(apiUrl, '/token/info');
    console.log(`   Name:               ${tokenInfo.name}`);
    console.log(`   Symbol:             ${tokenInfo.symbol}`);
    console.log(`   Decimals:           ${tokenInfo.decimals}`);
    console.log(`   Max supply:         ${tokenInfo.max_supply}`);
    console.log(`   Circulating supply: ${tokenInfo.circulating_supply}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('2. Account Balance');
  console.log('------------------');
  try {
    const balance = await fetchApi<BalanceInfo>(apiUrl, `/token/balance/${encodeURIComponent(did)}`);
    console.log(`   Account:   ${balance.account}`);
    console.log(`   Balance:   ${balance.balance} WILL`);
    console.log(`   Staked:    ${balance.staked} WILL`);
    console.log(`   Unbonding: ${balance.unbonding} WILL\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('3. Subgrove Balance');
  console.log('-------------------');
  const testSubgroveId = 'demo-subgrove';
  try {
    const sgBalance = await fetchApi<BalanceInfo>(
      apiUrl,
      `/token/subgrove/balance/${encodeURIComponent(testSubgroveId)}`,
    );
    console.log(`   Subgrove: ${testSubgroveId}`);
    console.log(`   Balance:  ${sgBalance.balance} WILL\n`);
  } catch (error) {
    console.log(`   Subgrove "${testSubgroveId}" not found or no balance\n`);
  }

  console.log('4. Fee Schedule');
  console.log('---------------');
  try {
    const fees = await fetchApi<FeeSchedule>(apiUrl, '/fees/schedule');
    console.log(`   Base TX cost:           ${fees.base_tx_cost} WILL`);
    console.log(`   Cost per byte:          ${fees.cost_per_byte} WILL`);
    console.log(`   Query fee:              ${fees.query_fee} WILL`);
    console.log(`   Transfer fee (bps):     ${fees.transfer_fee_percentage}`);
    console.log(`   Max TX size:            ${fees.max_tx_size_bytes} bytes`);
    console.log(`   Max data payload:       ${fees.max_data_payload_bytes} bytes\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('VALIDATOR OPERATIONS');
  console.log('====================\n');

  console.log('5. List Validators');
  console.log('------------------');
  let validators: Validator[] = [];
  try {
    validators = await fetchApi<Validator[]>(apiUrl, '/validators');
    console.log(`   Total validators: ${validators.length}`);
    if (validators.length > 0) {
      console.log('\n   Top validators:');
      validators.slice(0, 5).forEach((v, i) => {
        console.log(`   ${i + 1}. ${v.validator_did.substring(0, 24)}...`);
        console.log(`      Status:       ${v.status}`);
        console.log(`      Stake:        ${v.stake_amount} WILL`);
        console.log(`      Voting power: ${v.voting_power}`);
      });
    }
    console.log();
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('6. Validator Details');
  console.log('--------------------');
  if (validators.length > 0) {
    try {
      const v = await fetchApi<Validator>(
        apiUrl,
        `/validators/${encodeURIComponent(validators[0].validator_did)}`,
      );
      console.log(`   DID:          ${v.validator_did}`);
      console.log(`   Status:       ${v.status}`);
      console.log(`   Stake:        ${v.stake_amount} WILL`);
      console.log(`   Voting power: ${v.voting_power}`);
      if (v.consensus_pubkey) {
        console.log(`   Pubkey:       ${v.consensus_pubkey.substring(0, 24)}...`);
      }
      console.log();
    } catch (error) {
      console.log(`   Note: ${error}\n`);
    }
  } else {
    console.log('   No validators available to query\n');
  }

  console.log('7. Validator Set Summary');
  console.log('------------------------');
  try {
    const set = await fetchApi<ValidatorSet>(apiUrl, '/validators/set');
    console.log(`   Total:         ${set.total_validators}`);
    console.log(`   Active:        ${set.active_validators}`);
    console.log(`   Total staked:  ${set.total_staked} WILL`);
    console.log(`   Voting power:  ${set.total_voting_power}\n`);
  } catch (error) {
    console.log(`   Note: ${error}\n`);
  }

  console.log('ECONOMIC MODEL SUMMARY');
  console.log('======================');
  console.log('- WILL token for storage fees and staking');
  console.log('- Pay-per-storage model (automatic deduction from subgrove balance)');
  console.log('- Validators secure the network via Proof of Stake');
  console.log('- Indexers earn rewards for indexing work\n');

  console.log('Token and validator operations example complete!');
}

main().catch(console.error);
