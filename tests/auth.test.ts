import {
  signEd25519,
  verifyEd25519,
  generateEd25519KeyPair,
  getEd25519PublicKey,
  detectAlgorithm,
  algorithmFromKeyType,
  WillowAuth,
} from '../src/auth';
import { ed25519 } from '@noble/curves/ed25519';
import { ethers } from 'ethers';

describe('Auth', () => {
  const message = 'test message';

  describe('generateEd25519KeyPair', () => {
    it('should generate a valid key pair', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();

      expect(privateKey).toBeDefined();
      expect(publicKey).toBeDefined();
      expect(privateKey.length).toBe(64); // 32 bytes hex encoded
      expect(publicKey.length).toBe(64); // 32 bytes hex encoded
    });

    it('should generate unique key pairs', () => {
      const pair1 = generateEd25519KeyPair();
      const pair2 = generateEd25519KeyPair();

      expect(pair1.privateKey).not.toBe(pair2.privateKey);
      expect(pair1.publicKey).not.toBe(pair2.publicKey);
    });
  });

  describe('getEd25519PublicKey', () => {
    it('should derive public key from 32-byte private key', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const derivedPublicKey = getEd25519PublicKey(privateKey);

      expect(derivedPublicKey).toBe(publicKey);
    });

    it('should extract public key from 64-byte key (seed + public)', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const combinedKey = privateKey + publicKey; // 64 bytes = 128 hex chars

      const extractedPublicKey = getEd25519PublicKey(combinedKey);
      expect(extractedPublicKey).toBe(publicKey);
    });

    it('should throw for invalid key length', () => {
      expect(() => getEd25519PublicKey('aabb')).toThrow('Invalid Ed25519 private key length');
    });
  });

  describe('signEd25519', () => {
    it('should sign a message', () => {
      const { privateKey } = generateEd25519KeyPair();
      const signature = signEd25519(message, privateKey);

      expect(signature).toBeDefined();
      expect(signature.length).toBe(128); // 64 bytes hex encoded
    });

    it('should produce deterministic signatures', () => {
      const { privateKey } = generateEd25519KeyPair();
      const sig1 = signEd25519(message, privateKey);
      const sig2 = signEd25519(message, privateKey);

      expect(sig1).toBe(sig2);
    });

    it('should produce different signatures for different messages', () => {
      const { privateKey } = generateEd25519KeyPair();
      const sig1 = signEd25519('message1', privateKey);
      const sig2 = signEd25519('message2', privateKey);

      expect(sig1).not.toBe(sig2);
    });

    it('should handle 64-byte private keys (seed + public)', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const combinedKey = privateKey + publicKey;

      const signature = signEd25519(message, combinedKey);
      expect(signature).toBeDefined();
      expect(signature.length).toBe(128);
    });
  });

  describe('verifyEd25519', () => {
    it('should verify a valid signature', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const signature = signEd25519(message, privateKey);

      const isValid = verifyEd25519(message, signature, publicKey);
      expect(isValid).toBe(true);
    });

    it('should reject invalid signatures', () => {
      const { publicKey } = generateEd25519KeyPair();
      const invalidSig = 'a'.repeat(128);

      const isValid = verifyEd25519(message, invalidSig, publicKey);
      expect(isValid).toBe(false);
    });

    it('should reject wrong public key', () => {
      const { privateKey } = generateEd25519KeyPair();
      const { publicKey: wrongPublicKey } = generateEd25519KeyPair();

      const signature = signEd25519(message, privateKey);
      const isValid = verifyEd25519(message, signature, wrongPublicKey);
      expect(isValid).toBe(false);
    });

    it('should reject tampered message', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const signature = signEd25519(message, privateKey);

      const isValid = verifyEd25519('tampered message', signature, publicKey);
      expect(isValid).toBe(false);
    });

    it('should handle malformed inputs gracefully', () => {
      expect(verifyEd25519(message, 'invalid-hex', 'abc123')).toBe(false);
      expect(verifyEd25519(message, 'aa', 'bb')).toBe(false);
    });
  });

  describe('detectAlgorithm', () => {
    it('should detect secp256k1 from Ethereum DID', () => {
      expect(detectAlgorithm('did:eth:0x1234')).toBe('secp256k1');
      expect(detectAlgorithm('did:eip155:1:0x1234')).toBe('secp256k1');
    });

    it('should detect secp256k1 from 0x-prefixed key', () => {
      const ethKey = '0x' + 'a'.repeat(64);
      expect(detectAlgorithm('did:willow:test', ethKey)).toBe('secp256k1');
    });

    it('should detect Ed25519 from key length', () => {
      const ed25519Key32 = 'a'.repeat(64); // 32 bytes
      const ed25519Key64 = 'a'.repeat(128); // 64 bytes

      expect(detectAlgorithm('did:willow:test', ed25519Key32)).toBe('Ed25519');
      expect(detectAlgorithm('did:willow:test', ed25519Key64)).toBe('Ed25519');
    });

    it('should default to Ed25519 for Willow DIDs', () => {
      expect(detectAlgorithm('did:willow:test')).toBe('Ed25519');
    });
  });

  describe('algorithmFromKeyType', () => {
    it('maps the secp256k1 DID-document key type to secp256k1', () => {
      expect(algorithmFromKeyType('EcdsaSecp256k1VerificationKey2019')).toBe('secp256k1');
      expect(algorithmFromKeyType('EcdsaSecp256k1RecoveryMethod2020')).toBe('secp256k1');
    });

    it('maps Ed25519 key types to Ed25519', () => {
      expect(algorithmFromKeyType('Ed25519')).toBe('Ed25519');
      expect(algorithmFromKeyType('Ed25519VerificationKey2020')).toBe('Ed25519');
    });

    it('returns undefined for unknown / missing types so callers can fall back', () => {
      expect(algorithmFromKeyType('SomeFutureKey2099')).toBeUndefined();
      expect(algorithmFromKeyType(undefined)).toBeUndefined();
    });
  });

  describe('WillowAuth.signRequest algorithm selection (self-certifying DIDs)', () => {
    // Self-certifying Willow DIDs (did:willow:z<base58btc(hash)>) no longer
    // encode the algorithm, so the algorithm must be supplied explicitly (or
    // derived from the DID document) rather than parsed from the id string.
    const selfCertifyingDid =
      'did:willow:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

    it('signs with secp256k1 when the identity declares secp256k1', () => {
      const wallet = ethers.Wallet.createRandom();
      const auth = new WillowAuth('http://localhost:0');

      // Raw-hex (no 0x) secp256k1 private key: this is exactly the case the old
      // detectAlgorithm heuristic misclassified as Ed25519.
      const rawHexKey = wallet.privateKey.replace(/^0x/, '');
      expect(detectAlgorithm(selfCertifyingDid, rawHexKey)).toBe('Ed25519'); // fallback would be wrong

      auth.setIdentity(
        selfCertifyingDid,
        wallet.privateKey,
        `${selfCertifyingDid}#key-1`,
        'secp256k1',
      );

      const headers = auth.signRequest('GET', '/v1/data/query');
      const timestamp = headers['X-Timestamp'];
      const message = `GET:/v1/data/query:${timestamp}`;
      const messageHash = ethers.keccak256(ethers.toUtf8Bytes(message));

      // A secp256k1 signature recovers to the wallet's address; an Ed25519
      // signature would not be recoverable at all.
      const recovered = ethers.verifyMessage(
        ethers.getBytes(messageHash),
        '0x' + headers['X-Signature'],
      );
      expect(recovered.toLowerCase()).toBe(wallet.address.toLowerCase());
      // secp256k1 signatures are 65 bytes (130 hex chars); Ed25519 is 64 (128).
      expect(headers['X-Signature'].length).toBe(130);
    });

    it('defaults to Ed25519 signing when no algorithm is given', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const auth = new WillowAuth('http://localhost:0');

      auth.setIdentity(selfCertifyingDid, privateKey, `${selfCertifyingDid}#key-1`);

      const headers = auth.signRequest('POST', '/v1/data/write');
      const timestamp = headers['X-Timestamp'];
      const message = `POST:/v1/data/write:${timestamp}`;

      expect(headers['X-Signature'].length).toBe(128); // 64-byte Ed25519 sig
      expect(verifyEd25519(message, headers['X-Signature'], publicKey)).toBe(true);
    });

    it('lets an explicit algorithm override the private-key heuristic', () => {
      // A 0x-prefixed 66-char key would heuristically look like secp256k1, but
      // an explicit Ed25519 declaration must win.
      const { privateKey } = generateEd25519KeyPair();
      const auth = new WillowAuth('http://localhost:0');

      auth.setIdentity(
        selfCertifyingDid,
        privateKey,
        `${selfCertifyingDid}#key-1`,
        'Ed25519',
      );

      const headers = auth.signRequest('GET', '/v1/status');
      expect(headers['X-Signature'].length).toBe(128); // Ed25519, not secp256k1
    });
  });

  describe('Integration with @noble/curves', () => {
    it('should produce signatures verifiable by noble/curves directly', () => {
      const { privateKey, publicKey } = generateEd25519KeyPair();
      const signature = signEd25519(message, privateKey);

      // Verify using noble/curves directly
      const sigBytes = new Uint8Array(signature.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      const pubKeyBytes = new Uint8Array(publicKey.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      const msgBytes = new TextEncoder().encode(message);

      const isValid = ed25519.verify(sigBytes, msgBytes, pubKeyBytes);
      expect(isValid).toBe(true);
    });

    it('should verify signatures created by noble/curves directly', () => {
      const privateKey = ed25519.utils.randomPrivateKey();
      const publicKey = ed25519.getPublicKey(privateKey);

      const msgBytes = new TextEncoder().encode(message);
      const signature = ed25519.sign(msgBytes, privateKey);

      // Convert to hex
      const privateKeyHex = Array.from(privateKey, b => b.toString(16).padStart(2, '0')).join('');
      const publicKeyHex = Array.from(publicKey, b => b.toString(16).padStart(2, '0')).join('');
      const signatureHex = Array.from(signature, b => b.toString(16).padStart(2, '0')).join('');

      const isValid = verifyEd25519(message, signatureHex, publicKeyHex);
      expect(isValid).toBe(true);
    });
  });
});
