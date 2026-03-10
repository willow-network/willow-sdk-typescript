/**
 * ERC-8004 (Trustless Agents) integration for Willow.
 *
 * Provides helpers to link Ethereum addresses to Willow DIDs and interact
 * with on-chain ERC-8004 agent registrations.
 */

// ── Transaction types ──────────────────────────────────────────────────

export interface LinkEthAddressTx {
  did: string;
  ethAddress: string; // hex with 0x prefix
  publicKeyId: string;
  signature?: string;
  nonce?: number;
}

export interface RegisterErc8004AgentTx {
  did: string;
  chainId: number;
  registryAddress: string; // hex with 0x prefix
  agentId: number;
  agentUri: string;
  signature?: string;
  publicKeyId?: string;
  nonce?: number;
}

// ── Response types ─────────────────────────────────────────────────────

export interface AgentReputationSummary {
  checkpoint_success_rate: number;
  verification_accuracy: number;
  active_days: number;
  last_updated: number;
}

export interface AgentRegistrationJson {
  type: string;
  name: string;
  description: string;
  services: AgentService[];
  x402_support: boolean;
  active: boolean;
  registrations: AgentChainRegistration[];
  supported_trust: string[];
  reputation?: AgentReputationSummary;
}

export interface ReputationAttestation {
  did: string;
  metrics: Record<string, unknown>;
  proof: string;
  block_height: number;
  last_updated: number;
}

export interface ReputationHistoryEvent {
  event_type: string;
  block_height: number;
  timestamp: number;
  reference: string | null;
}

export interface ReputationHistoryResponse {
  did: string;
  events: ReputationHistoryEvent[];
  total_events: number;
}

export interface AgentService {
  name: string;
  endpoint: string;
}

export interface AgentChainRegistration {
  chain_id: number;
  registry: string;
  agent_id: number;
}

export interface Erc8004Registration {
  chain_id: number;
  registry_address: number[]; // 20-byte array
  agent_id: number;
  agent_uri: string;
  registered_at: number;
}

// ── Validation Registry types ──────────────────────────────────────────

export interface Erc8004ValidationRecord {
  request_hash: string;
  subgrove_id: string;
  block_range: [number, number];
  state_root: string;
  response: number;
  status: string;
  tee_verified: boolean;
  tee_type: string | null;
  submitted_at_block: number;
  challenge_deadline: number | null;
  tag: string;
}

export interface Erc8004ValidationStatusResponse {
  did: string;
  validations: Erc8004ValidationRecord[];
  total: number;
}

export interface ValidationStatusBreakdown {
  trusted: number;
  pending_challenge: number;
  tee_attested: number;
  disputed: number;
  invalidated: number;
}

export interface DisputeStats {
  disputes_won_as_defendant: number;
  disputes_lost_as_defendant: number;
  disputes_won_as_challenger: number;
  disputes_lost_as_challenger: number;
}

export interface Erc8004ValidationSummary {
  did: string;
  count: number;
  average_response: number;
  status_breakdown: ValidationStatusBreakdown;
  dispute_stats: DisputeStats;
}

// ── Agent Discovery types ─────────────────────────────────────────────

export interface Erc8004AgentListItem {
  did: string;
  eth_address: string | null;
  agent_uri: string;
  chain_id: number;
  agent_id: number;
  validation_count: number;
  registered_at: number;
}

export interface Erc8004AgentListResponse {
  agents: Erc8004AgentListItem[];
  total: number;
  offset: number;
  limit: number;
}

// ── Client ─────────────────────────────────────────────────────────────

export class Erc8004Client {
  private apiUrl: string;

  constructor(apiUrl: string) {
    this.apiUrl = apiUrl.replace(/\/+$/, '');
  }

  /** List/search ERC-8004 registered agents with optional filters. */
  async listAgents(options?: {
    limit?: number;
    offset?: number;
  }): Promise<Erc8004AgentListResponse> {
    const params: string[] = [];
    if (options?.limit !== undefined) params.push(`limit=${options.limit}`);
    if (options?.offset !== undefined) params.push(`offset=${options.offset}`);
    const qs = params.length > 0 ? `?${params.join('&')}` : '';
    const resp = await fetch(`${this.apiUrl}/agents${qs}`);
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(body.error || 'Failed to list agents');
    }
    return body.data;
  }

  /** Fetch the ERC-8004 registration JSON for an agent DID. */
  async getAgentRegistration(did: string): Promise<AgentRegistrationJson> {
    const resp = await fetch(
      `${this.apiUrl}/agent/${encodeURIComponent(did)}/registration.json`,
    );
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(body.error || 'Failed to fetch agent registration');
    }
    return body.data;
  }

  /** Get the ETH address linked to a DID. */
  async getEthAddress(did: string): Promise<string | null> {
    const resp = await fetch(
      `${this.apiUrl}/did/${encodeURIComponent(did)}/eth-address`,
    );
    if (resp.status === 404) return null;
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(body.error || 'Failed to fetch ETH address');
    }
    return body.data?.eth_address ?? null;
  }

  /** Get the DID linked to an ETH address. */
  async getDidForEth(ethAddress: string): Promise<string | null> {
    const resp = await fetch(
      `${this.apiUrl}/eth-address/${encodeURIComponent(ethAddress)}/did`,
    );
    if (resp.status === 404) return null;
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(body.error || 'Failed to fetch DID');
    }
    return body.data?.did ?? null;
  }

  /** Get stored ERC-8004 registration details for a DID. */
  async getErc8004Details(did: string): Promise<Erc8004Registration | null> {
    const resp = await fetch(
      `${this.apiUrl}/did/${encodeURIComponent(did)}/erc8004`,
    );
    if (resp.status === 404) return null;
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(body.error || 'Failed to fetch ERC-8004 details');
    }
    return body.data ?? null;
  }

  /** Fetch reputation attestation with GroveDB Merkle proof for a DID. */
  async getReputationAttestation(
    did: string,
  ): Promise<ReputationAttestation> {
    const resp = await fetch(
      `${this.apiUrl}/agent/${encodeURIComponent(did)}/reputation-attestation`,
    );
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(
        body.error || 'Failed to fetch reputation attestation',
      );
    }
    return body.data;
  }

  /** Fetch ERC-8004 formatted reputation history for a DID. */
  async getReputationHistory(
    did: string,
    limit?: number,
  ): Promise<ReputationHistoryResponse> {
    const params = limit !== undefined ? `?limit=${limit}` : '';
    const resp = await fetch(
      `${this.apiUrl}/agent/${encodeURIComponent(did)}/reputation-history${params}`,
    );
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(
        body.error || 'Failed to fetch reputation history',
      );
    }
    return body.data;
  }

  /** Fetch ERC-8004 validation status (checkpoint validations) for a DID. */
  async getValidationStatus(
    did: string,
    limit?: number,
    subgroveId?: string,
  ): Promise<Erc8004ValidationStatusResponse> {
    const params: string[] = [];
    if (limit !== undefined) params.push(`limit=${limit}`);
    if (subgroveId !== undefined) params.push(`subgrove_id=${encodeURIComponent(subgroveId)}`);
    const qs = params.length > 0 ? `?${params.join('&')}` : '';
    const resp = await fetch(
      `${this.apiUrl}/agent/${encodeURIComponent(did)}/validation-status${qs}`,
    );
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(
        body.error || 'Failed to fetch validation status',
      );
    }
    return body.data;
  }

  /** Fetch aggregated ERC-8004 validation summary for a DID. */
  async getValidationSummary(
    did: string,
    subgroveId?: string,
  ): Promise<Erc8004ValidationSummary> {
    const qs = subgroveId !== undefined
      ? `?subgrove_id=${encodeURIComponent(subgroveId)}`
      : '';
    const resp = await fetch(
      `${this.apiUrl}/agent/${encodeURIComponent(did)}/validation-summary${qs}`,
    );
    const body = await resp.json() as any;
    if (body.success === false) {
      throw new Error(
        body.error || 'Failed to fetch validation summary',
      );
    }
    return body.data;
  }
}
