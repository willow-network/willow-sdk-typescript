import * as fs from 'fs';
import * as path from 'path';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { secp256k1 } from '@noble/curves/secp256k1';
import { verifyEd25519, verifySecp256k1 } from '../src/auth';
import { WillowClient } from '../src/client';
import { createDidFromPublicKey } from '../src/utils';

/**
 * `WillowClient` signs each transaction with its identity's own algorithm.
 * A secp256k1 identity's transactions were signed as Ed25519 with its key,
 * and never verified.
 */

const KAT = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'signed_messages_kat.json'), 'utf8'),
);
const SEED: string = KAT.private_key_seed_hex;
const STORE = KAT.vectors.find((v: any) => v.name === 'StoreData');

function jsonResponse(body: unknown) {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

const realFetch = global.fetch;
let bodies: any[] = [];
beforeEach(() => {
  bodies = [];
  global.fetch = jest.fn(async (url: string, init?: RequestInit) => {
    if (url.includes('/nonce')) {
      return jsonResponse({ success: true, data: { nonce: STORE.inputs.nonce - 1 } });
    }
    bodies.push(JSON.parse(init!.body as string));
    return jsonResponse({ success: true, data: { tx_hash: 'AB12', code: 0, log: '' } });
  }) as unknown as typeof fetch;
});
afterAll(() => {
  global.fetch = realFetch;
});

function client(algorithm: 'Ed25519' | 'secp256k1', did = STORE.inputs.owner_did) {
  const c = new WillowClient({ apiUrl: 'http://api.test', consensusRpcUrl: 'http://rpc.test' });
  c.auth.setIdentity(did, SEED, `${did}#key-1`, algorithm);
  return c;
}

const signatureHex = (w: any) => bytesToHex(Uint8Array.from(w.signature));

describe('WillowClient signs with its identity\'s algorithm', () => {
  it('store under a secp256k1 identity sends the known secp256k1 signature', async () => {
    await client('secp256k1').store(
      STORE.inputs.subgrove_id,
      STORE.inputs.key,
      JSON.parse(STORE.inputs.data_utf8),
    );
    const w = bodies[0].StoreData;
    expect(w.signature).toHaveLength(64);
    expect(signatureHex(w)).toBe(STORE.secp256k1_compact_signature_hex);
    expect(verifySecp256k1(STORE.message, `0x${signatureHex(w)}`, KAT.secp256k1_public_key_compressed_hex)).toBe(true);
  });

  it('store under an Ed25519 identity still sends the known Ed25519 signature', async () => {
    await client('Ed25519').store(
      STORE.inputs.subgrove_id,
      STORE.inputs.key,
      JSON.parse(STORE.inputs.data_utf8),
    );
    expect(signatureHex(bodies[0].StoreData)).toBe(STORE.ed25519_signature_hex);
  });

  it('registerDid under a secp256k1 identity signs the document as the chain writes it', async () => {
    const pub = bytesToHex(secp256k1.getPublicKey(hexToBytes(SEED), true));
    const doc = { ...createDidFromPublicKey(pub, 'secp256k1'), created: 7, updated: 7 };
    const keyId = `${doc.id}#key-1`;
    await client('secp256k1', doc.id).registerDid(doc);

    const tx = bodies[0].RegisterDid;
    expect(tx.nonce).toBe(1);
    // The JSON text the node signs: serde's field order, optional fields as null.
    const text =
      `{"id":"${doc.id}","public_keys":[{"id":"${keyId}",` +
      `"type":"EcdsaSecp256k1VerificationKey2019","controller":"${doc.id}",` +
      `"public_key_base58":null,"public_key_hex":"${pub}"}],` +
      `"authentication":["${keyId}"],"service":[],"created":7,"updated":7,"proof":null}`;
    expect(JSON.stringify(tx.did_document)).toBe(text);
    expect(verifySecp256k1(text, `0x${signatureHex(tx)}`, pub)).toBe(true);
    expect(verifyEd25519(text, signatureHex(tx), KAT.ed25519_public_key_hex)).toBe(false);
  });
});
