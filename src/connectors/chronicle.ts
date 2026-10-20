/**
 * BrowserDefense Google Chronicle/SecOps Connector
 *
 * Sends forensics events to Google Chronicle Ingestion API using UDM format.
 * Uses Google Cloud service account authentication.
 *
 * @see https://cloud.google.com/chronicle/docs/reference/ingestion-api
 */

import { BaseConnector, type EventTransformer } from './base';
import {
  type ChronicleConnectorConfig,
  type ForensicsEvent,
  type SendResult,
} from './types';

// =============================================================================
// Types
// =============================================================================

/**
 * Google Cloud service account credentials.
 */
interface ServiceAccountCredentials {
  type: 'service_account';
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
  auth_provider_x509_cert_url: string;
  client_x509_cert_url: string;
}

/**
 * OAuth2 token response from Google.
 */
interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

/**
 * UDM Event structure for Chronicle.
 * @see https://cloud.google.com/chronicle/docs/reference/udm-field-list
 */
interface UdmEvent {
  metadata: {
    event_timestamp: string;
    event_type: string;
    product_name: string;
    vendor_name: string;
    product_log_id?: string;
    description?: string;
  };
  principal?: {
    hostname?: string;
    user?: {
      userid?: string;
      email_addresses?: string[];
    };
    asset?: {
      hostname?: string;
      asset_id?: string;
    };
  };
  target: {
    url?: string;
    hostname?: string;
  };
  network?: {
    http?: {
      referral_url?: string;
      user_agent?: string;
    };
  };
  security_result: Array<{
    action: string[];
    category_details?: string[];
    severity?: string;
    rule_name?: string;
    description?: string;
  }>;
  additional?: {
    fields?: Record<string, { string_value?: string; int_value?: number }>;
  };
}

/**
 * Chronicle batch create events request.
 */
interface BatchCreateEventsRequest {
  customer_id: string;
  log_type?: string;
  events: Array<{ udm: UdmEvent }>;
  labels?: Array<{ key: string; value: string }>;
}

/**
 * Chronicle batch create events response.
 */
interface BatchCreateEventsResponse {
  // Chronicle returns empty object on success
}

// =============================================================================
// Chronicle Connector Implementation
// =============================================================================

/**
 * Regional endpoint mapping for Chronicle Ingestion API.
 */
const CHRONICLE_ENDPOINTS: Record<string, string> = {
  us: 'https://malachiteingestion-pa.googleapis.com',
  europe: 'https://europe-malachiteingestion-pa.googleapis.com',
  'asia-southeast1': 'https://asia-southeast1-malachiteingestion-pa.googleapis.com',
};

/**
 * Google OAuth2 token URL.
 */
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';

/**
 * Chronicle Ingestion API scope.
 */
const CHRONICLE_SCOPE = 'https://www.googleapis.com/auth/malachite-ingestion';

/**
 * Google Chronicle/SecOps connector.
 *
 * Sends forensics events to Chronicle using the Ingestion API.
 * Transforms events to UDM (Unified Data Model) format.
 *
 * @example
 * ```typescript
 * const connector = new ChronicleConnector({
 *   name: 'chronicle-prod',
 *   enabled: true,
 *   type: 'chronicle',
 *   customerId: 'your-customer-id',
 *   region: 'us',
 *   credentials: '/path/to/service-account.json',
 *   logType: 'BROWSERDEFENSE',
 * });
 *
 * await connector.init();
 * await connector.send(event);
 * ```
 */
export class ChronicleConnector extends BaseConnector {
  readonly type = 'chronicle' as const;

  private readonly customerId: string;
  private readonly region: string;
  private readonly logType: string;
  private readonly labels?: Array<{ key: string; value: string }>;
  private credentials: ServiceAccountCredentials | null = null;
  private credentialsSource: string | ServiceAccountCredentials;

  // Token cache
  private accessToken: string | null = null;
  private tokenExpiresAt: number = 0;

  // HTTP client
  private readonly baseUrl: string;

  constructor(config: ChronicleConnectorConfig) {
    super(config);
    this.customerId = config.customerId;
    this.region = config.region;
    this.logType = config.logType ?? 'BROWSERDEFENSE';
    this.labels = config.labels;
    this.credentialsSource = config.credentials;

    // Set base URL from region
    this.baseUrl = CHRONICLE_ENDPOINTS[config.region];
    if (!this.baseUrl) {
      throw new Error(`Unknown Chronicle region: ${config.region}`);
    }
  }

  // ===========================================================================
  // Abstract method implementations
  // ===========================================================================

  protected async doInit(): Promise<void> {
    // Load credentials
    this.credentials = await this.loadCredentials(this.credentialsSource);

    // Validate credentials
    if (!this.credentials.client_email) {
      throw new Error('Chronicle credentials missing client_email');
    }
    if (!this.credentials.private_key) {
      throw new Error('Chronicle credentials missing private_key');
    }

    // Test auth by getting a token
    await this.getAccessToken();
  }

  protected async doSend(event: ForensicsEvent): Promise<SendResult> {
    try {
      const token = await this.getAccessToken();
      const udmEvent = this.transformToUdm(event);

      const request: BatchCreateEventsRequest = {
        customer_id: this.customerId,
        log_type: this.logType,
        events: [{ udm: udmEvent }],
      };

      if (this.labels && this.labels.length > 0) {
        request.labels = this.labels;
      }

      const response = await this.sendToChronicle(token, request);

      return {
        success: true,
        eventId: event.eventId,
        response: response as Record<string, unknown>,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const retryable = this.isRetryableError(error);

      return {
        success: false,
        eventId: event.eventId,
        error: errorMessage,
        retryable,
      };
    }
  }

  protected async doHealth(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Try to get a token to verify auth
      await this.getAccessToken();
      return {
        healthy: true,
        message: `Connected to Chronicle (${this.region})`,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        healthy: false,
        message: `Chronicle auth failed: ${errorMessage}`,
      };
    }
  }

  protected async doClose(): Promise<void> {
    // Clear token cache
    this.accessToken = null;
    this.tokenExpiresAt = 0;
  }

  // ===========================================================================
  // Batch override for efficiency
  // ===========================================================================

  /**
   * Override sendBatch to use Chronicle's batch API.
   */
  async sendBatch(events: ForensicsEvent[]): Promise<SendResult[]> {
    this.ensureInitialized();

    // Filter events
    const toProcess = events.filter((e) => this.shouldProcess(e));
    const filteredEvents = events.filter((e) => !this.shouldProcess(e));

    // Create filtered results
    const filteredResults: SendResult[] = filteredEvents.map((e) => ({
      success: true,
      eventId: e.eventId,
      response: { filtered: true },
    }));

    if (toProcess.length === 0) {
      return filteredResults;
    }

    try {
      const token = await this.getAccessToken();
      const udmEvents = toProcess.map((e) => ({ udm: this.transformToUdm(e) }));

      const request: BatchCreateEventsRequest = {
        customer_id: this.customerId,
        log_type: this.logType,
        events: udmEvents,
      };

      if (this.labels && this.labels.length > 0) {
        request.labels = this.labels;
      }

      await this.sendToChronicle(token, request);

      // All events succeeded
      const successResults: SendResult[] = toProcess.map((e) => ({
        success: true,
        eventId: e.eventId,
        response: { batched: true },
      }));

      return [...successResults, ...filteredResults];
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const retryable = this.isRetryableError(error);

      // All events failed
      const failedResults: SendResult[] = toProcess.map((e) => ({
        success: false,
        eventId: e.eventId,
        error: errorMessage,
        retryable,
      }));

      return [...failedResults, ...filteredResults];
    }
  }

  // ===========================================================================
  // Private methods
  // ===========================================================================

  /**
   * Load service account credentials from various sources.
   */
  private async loadCredentials(
    source: string | ServiceAccountCredentials
  ): Promise<ServiceAccountCredentials> {
    // If it's already an object, return it
    if (typeof source === 'object') {
      return source;
    }

    // If it's a JSON string, parse it
    if (source.startsWith('{')) {
      try {
        return JSON.parse(source) as ServiceAccountCredentials;
      } catch {
        throw new Error('Invalid JSON in Chronicle credentials string');
      }
    }

    // Otherwise, treat as file path
    // In a browser environment, this would need to be handled differently
    // For now, throw an error suggesting inline credentials
    throw new Error(
      'File-based credentials not supported in browser environment. ' +
        'Provide credentials as JSON string or inline object.'
    );
  }

  /**
   * Get a valid access token, refreshing if necessary.
   */
  private async getAccessToken(): Promise<string> {
    // Check if we have a valid cached token (with 5 min buffer)
    const now = Date.now();
    if (this.accessToken && this.tokenExpiresAt > now + 5 * 60 * 1000) {
      return this.accessToken;
    }

    // Get new token
    const token = await this.fetchAccessToken();
    return token;
  }

  /**
   * Fetch a new access token using service account JWT.
   */
  private async fetchAccessToken(): Promise<string> {
    if (!this.credentials) {
      throw new Error('Credentials not loaded');
    }

    const jwt = await this.createSignedJwt();

    const response = await fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to get access token: ${response.status} ${errorText}`);
    }

    const tokenData = (await response.json()) as TokenResponse;

    // Cache the token
    this.accessToken = tokenData.access_token;
    this.tokenExpiresAt = Date.now() + tokenData.expires_in * 1000;

    return this.accessToken;
  }

  /**
   * Create a signed JWT for service account authentication.
   */
  private async createSignedJwt(): Promise<string> {
    if (!this.credentials) {
      throw new Error('Credentials not loaded');
    }

    const now = Math.floor(Date.now() / 1000);
    const header = {
      alg: 'RS256',
      typ: 'JWT',
    };

    const payload = {
      iss: this.credentials.client_email,
      sub: this.credentials.client_email,
      aud: GOOGLE_TOKEN_URL,
      iat: now,
      exp: now + 3600, // 1 hour
      scope: CHRONICLE_SCOPE,
    };

    const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
    const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    // Sign with RSA-SHA256
    const signature = await this.signWithRsaSha256(
      signingInput,
      this.credentials.private_key
    );

    return `${signingInput}.${signature}`;
  }

  /**
   * Sign data with RSA-SHA256 using the service account private key.
   */
  private async signWithRsaSha256(data: string, privateKeyPem: string): Promise<string> {
    // Import the private key
    const privateKey = await this.importPrivateKey(privateKeyPem);

    // Sign the data
    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      encoder.encode(data)
    );

    return this.base64UrlEncode(signature);
  }

  /**
   * Import a PEM-encoded RSA private key.
   */
  private async importPrivateKey(pem: string): Promise<CryptoKey> {
    // Remove PEM headers and newlines
    const pemContents = pem
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\s/g, '');

    // Decode base64
    const binaryString = atob(pemContents);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    // Import the key
    return crypto.subtle.importKey(
      'pkcs8',
      bytes,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );
  }

  /**
   * Base64 URL encode data (for JWT).
   */
  private base64UrlEncode(data: string | ArrayBuffer): string {
    let base64: string;

    if (typeof data === 'string') {
      base64 = btoa(data);
    } else {
      const bytes = new Uint8Array(data);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      base64 = btoa(binary);
    }

    // Convert to URL-safe base64
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Send events to Chronicle Ingestion API.
   */
  private async sendToChronicle(
    token: string,
    request: BatchCreateEventsRequest
  ): Promise<BatchCreateEventsResponse> {
    const url = `${this.baseUrl}/v2/udmevents:batchCreate`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new ChronicleApiError(
        `Chronicle API error: ${response.status} ${errorText}`,
        response.status
      );
    }

    // Chronicle returns empty object on success
    return {} as BatchCreateEventsResponse;
  }

  /**
   * Transform a ForensicsEvent to UDM format.
   */
  private transformToUdm: EventTransformer<UdmEvent> = (event) => {
    // Map matchType to UDM category
    const categoryMap: Record<string, string[]> = {
      domain: ['MALWARE_CATEGORY_PHISHING'],
      url: ['MALWARE_CATEGORY_MALICIOUS_URL'],
      hash: ['MALWARE_CATEGORY_MALWARE'],
    };

    // Determine action - defaults to 'block' for backward compatibility
    const action = event.action ?? 'block';
    const isUnblock = action === 'unblock';

    // Map to UDM action values
    const udmAction = isUnblock ? 'ALLOW' : 'BLOCK';
    const actionVerb = isUnblock ? 'Unblocked' : 'Blocked';
    const actionVerbLower = isUnblock ? 'unblocked' : 'blocked';

    const udmEvent: UdmEvent = {
      metadata: {
        event_timestamp: event.timestamp,
        event_type: 'NETWORK_HTTP',
        product_name: 'BrowserDefense',
        vendor_name: 'BrowserDefense',
        product_log_id: event.eventId,
        description: `${actionVerb} ${event.matchType} indicator: ${event.matchedIndicator}`,
      },
      principal: {
        hostname: event.orgId,
        ...(event.userId && {
          user: {
            userid: event.userId,
          },
        }),
        ...(event.deviceId && {
          asset: {
            asset_id: event.deviceId,
          },
        }),
      },
      target: {
        url: event.blockedUrl,
        hostname: this.extractHostname(event.blockedUrl),
      },
      network: {
        http: {
          referral_url: event.redirectChain[0] || event.tabContext.initiatorUrl,
        },
      },
      security_result: [
        {
          action: [udmAction],
          category_details: categoryMap[event.matchType] || ['UNKNOWN_CATEGORY'],
          severity: isUnblock ? 'LOW' : 'MEDIUM',
          rule_name: `browserdefense_${event.matchType}_${actionVerbLower}`,
          description: `${actionVerb} navigation to IOC: ${event.matchedIndicator}`,
        },
      ],
      additional: {
        fields: {
          org_id: { string_value: event.orgId },
          match_type: { string_value: event.matchType },
          matched_indicator: { string_value: event.matchedIndicator },
          ioc_action: { string_value: action },
          tab_id: { int_value: event.tabContext.tabId },
          incognito: { string_value: event.tabContext.incognito ? 'true' : 'false' },
          redirect_chain_length: { int_value: event.redirectChain.length },
        },
      },
    };

    // Add tab context if available
    if (event.tabContext.tabTitle) {
      udmEvent.additional!.fields!['tab_title'] = {
        string_value: event.tabContext.tabTitle,
      };
    }

    return udmEvent;
  };

  /**
   * Extract hostname from URL.
   */
  private extractHostname(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  /**
   * Check if an error is retryable.
   */
  private isRetryableError(error: unknown): boolean {
    if (error instanceof ChronicleApiError) {
      // Retry on 429 (rate limit), 5xx (server errors)
      return error.statusCode === 429 || error.statusCode >= 500;
    }

    // Retry on network errors
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return true;
    }

    return false;
  }
}

// =============================================================================
// Custom Error Types
// =============================================================================

/**
 * Chronicle API error with status code.
 */
export class ChronicleApiError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number
  ) {
    super(message);
    this.name = 'ChronicleApiError';
  }
}

// =============================================================================
// Factory Registration
// =============================================================================

import { connectorRegistry } from './base';

/**
 * Register the Chronicle connector factory.
 */
connectorRegistry.register('chronicle', (config) => {
  return new ChronicleConnector(config as ChronicleConnectorConfig);
});
