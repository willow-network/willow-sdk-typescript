import { WillowError } from '../types';

/**
 * Verifiable RPC routes (`/verifiable-rpc/*`, `/circuit/*`, `/vk/*`) are
 * served by indexers, not the API. Throws a config error when no indexer URL
 * was given, instead of sending the request somewhere that can't answer it.
 */
export function requireIndexerUrl(indexerBaseUrl: string): void {
  if (!indexerBaseUrl) {
    throw new WillowError(
      'Verifiable RPC reads are served by indexers, not the API: set `indexerUrl` in the WillowClient config.',
      'INDEXER_URL_REQUIRED',
    );
  }
}
