import {
  deriveDid,
  createDidFromPublicKey,
  createDidFromWallet,
  generateWallet,
  isValidDid,
} from '../src/utils';
import { secp256k1 } from '@noble/curves/secp256k1';

describe('Self-certifying Willow DIDs', () => {
  describe('deriveDid (Ed25519)', () => {
    // MANDATORY acceptance vector. The chain's RegisterDid check accepts only
    // this exact derivation, so this MUST match byte-for-byte:
    //   did = "did:willow:z" + base58btc(SHA3-256(0xED01 || pubkey))
    const PUBKEY_HEX =
      'a003201e65e47d578ad9bb17cb1d3590e9f504f55eac6ee40002e3ab9517c49c';
    const EXPECTED_DID =
      'did:willow:zDZ1Qqspppayjd9LF3Pkebq64Fa2PuK8zFQDDc11citB2';

    it('reproduces the mandatory Ed25519 acceptance vector exactly', () => {
      const { did } = deriveDid(PUBKEY_HEX, 'Ed25519');
      expect(did).toBe(EXPECTED_DID);
    });

    it('defaults to Ed25519 when no algorithm is given', () => {
      expect(deriveDid(PUBKEY_HEX).did).toBe(EXPECTED_DID);
    });

    it('accepts raw bytes as well as hex', () => {
      const bytes = Uint8Array.from(Buffer.from(PUBKEY_HEX, 'hex'));
      expect(deriveDid(bytes, 'Ed25519').did).toBe(EXPECTED_DID);
    });

    it('accepts a 0x-prefixed hex public key', () => {
      expect(deriveDid('0x' + PUBKEY_HEX, 'Ed25519').did).toBe(EXPECTED_DID);
    });

    it('derives the conventional #key-1 public key id', () => {
      const { did, publicKeyId } = deriveDid(PUBKEY_HEX, 'Ed25519');
      expect(publicKeyId).toBe(`${did}#key-1`);
    });

    it('produces a well-formed multibase-z did:willow id', () => {
      const { did } = deriveDid(PUBKEY_HEX, 'Ed25519');
      expect(did.startsWith('did:willow:z')).toBe(true);
      expect(isValidDid(did)).toBe(true);
    });
  });

  describe('createDidFromPublicKey', () => {
    const PUBKEY_HEX =
      'a003201e65e47d578ad9bb17cb1d3590e9f504f55eac6ee40002e3ab9517c49c';
    const EXPECTED_DID =
      'did:willow:zDZ1Qqspppayjd9LF3Pkebq64Fa2PuK8zFQDDc11citB2';

    it('builds a DID document with the derived self-certifying id', () => {
      const doc = createDidFromPublicKey(PUBKEY_HEX, 'Ed25519');
      expect(doc.id).toBe(EXPECTED_DID);
      expect(doc.publicKeys).toHaveLength(1);
      expect(doc.publicKeys[0].id).toBe(`${EXPECTED_DID}#key-1`);
      expect(doc.publicKeys[0].type).toBe('Ed25519');
      expect(doc.publicKeys[0].publicKeyHex).toBe(PUBKEY_HEX);
    });
  });

  describe('secp256k1 derivation', () => {
    // Deterministic secp256k1 key (the devnet test private key) — used only to
    // exercise the compressed-vs-uncompressed normalization path.
    const PRIV_HEX =
      'b5ecc03536f5e039e3c5bc46ad178d7faf80cee5f063016a4f4084e163409b3c';
    const priv = Uint8Array.from(Buffer.from(PRIV_HEX, 'hex'));
    const compressed = secp256k1.ProjectivePoint.fromPrivateKey(priv).toRawBytes(true);
    const uncompressed = secp256k1.ProjectivePoint.fromPrivateKey(priv).toRawBytes(false);

    it('hashes the COMPRESSED key: compressed and uncompressed inputs agree', () => {
      const fromCompressed = deriveDid(compressed, 'secp256k1').did;
      const fromUncompressed = deriveDid(uncompressed, 'secp256k1').did;
      expect(fromCompressed).toBe(fromUncompressed);
      expect(fromCompressed.startsWith('did:willow:z')).toBe(true);
    });

    it('accepts the 64-byte raw x||y form (no 0x04 prefix)', () => {
      const raw = uncompressed.slice(1); // strip the 0x04 SEC1 tag
      expect(deriveDid(raw, 'secp256k1').did).toBe(deriveDid(compressed, 'secp256k1').did);
    });

    it('differs from the Ed25519 derivation for the same key bytes', () => {
      // Different multicodec prefix => different id.
      expect(deriveDid(compressed, 'secp256k1').did).not.toBe(
        deriveDid(compressed, 'Ed25519').did
      );
    });
  });

  describe('createDidFromWallet', () => {
    it('derives a self-certifying id, not the old did:willow:eth: form', () => {
      const wallet = generateWallet();
      const doc = createDidFromWallet(wallet);
      expect(doc.id.startsWith('did:willow:z')).toBe(true);
      expect(doc.id.startsWith('did:willow:eth:')).toBe(false);
      expect(doc.publicKeys[0].id).toBe(`${doc.id}#key-1`);
      expect(isValidDid(doc.id)).toBe(true);
    });

    it('matches deriveDid over the wallet public key', () => {
      const wallet = generateWallet();
      const doc = createDidFromWallet(wallet);
      expect(doc.id).toBe(deriveDid(wallet.publicKey, 'secp256k1').did);
    });
  });
});
