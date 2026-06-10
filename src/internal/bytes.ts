/**
 * Shared byte-encoding helpers.
 *
 * Hex codecs re-export the canonical implementations from the grovedb
 * bincode module. UTF-8 and base64 codecs are pure JS — TextEncoder /
 * TextDecoder and atob / btoa, all global in Node >= 18 and browsers —
 * so nothing here depends on `Buffer`.
 */

export { bytesToHex, hexToBytes } from '../grovedb/bincode';

export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}
