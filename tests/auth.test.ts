import {
  signEd25519,
  verifyEd25519,
  generateEd25519KeyPair,
  getEd25519PublicKey,
  detectAlgorithm
} from '../src/auth';
import { ed25519 } from '@noble/curves/ed25519';

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
