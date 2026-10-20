/**
 * Test HTTP Server Utility for Connector Integration Tests
 *
 * Provides a local HTTP server that can be configured to return specific
 * responses, simulate failures, track requests, and test retry behavior.
 */

import { createServer, Server, IncomingMessage, ServerResponse } from 'http';
import { AddressInfo } from 'net';

/**
 * Recorded request from the test server.
 */
export interface RecordedRequest {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  timestamp: number;
}

/**
 * Response configuration for the test server.
 */
export interface ResponseConfig {
  statusCode: number;
  body: string | object;
  headers?: Record<string, string>;
  delay?: number;
}

/**
 * Test HTTP server that records requests and returns configurable responses.
 */
export class TestHttpServer {
  private server: Server | null = null;
  private requests: RecordedRequest[] = [];
  private responseQueue: ResponseConfig[] = [];
  private defaultResponse: ResponseConfig = {
    statusCode: 200,
    body: { success: true },
  };

  /**
   * Start the server on a random available port.
   */
  async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => this.handleRequest(req, res));

      this.server.on('error', reject);

      this.server.listen(0, '127.0.0.1', () => {
        const address = this.server!.address() as AddressInfo;
        resolve(address.port);
      });
    });
  }

  /**
   * Stop the server and clear all recorded data.
   */
  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }

      this.server.close((err) => {
        if (err) {
          reject(err);
        } else {
          this.server = null;
          this.requests = [];
          this.responseQueue = [];
          resolve();
        }
      });
    });
  }

  /**
   * Get the base URL for the server.
   */
  get baseUrl(): string {
    if (!this.server) {
      throw new Error('Server not started');
    }
    const address = this.server.address() as AddressInfo;
    return `http://127.0.0.1:${address.port}`;
  }

  /**
   * Queue a response to be returned for the next request.
   * Queued responses are consumed in order (FIFO).
   */
  queueResponse(config: ResponseConfig): void {
    this.responseQueue.push(config);
  }

  /**
   * Queue multiple responses at once.
   */
  queueResponses(configs: ResponseConfig[]): void {
    this.responseQueue.push(...configs);
  }

  /**
   * Set the default response to return when no queued responses remain.
   */
  setDefaultResponse(config: ResponseConfig): void {
    this.defaultResponse = config;
  }

  /**
   * Get all recorded requests.
   */
  getRequests(): RecordedRequest[] {
    return [...this.requests];
  }

  /**
   * Get the last recorded request.
   */
  getLastRequest(): RecordedRequest | undefined {
    return this.requests[this.requests.length - 1];
  }

  /**
   * Clear recorded requests.
   */
  clearRequests(): void {
    this.requests = [];
  }

  /**
   * Clear the response queue.
   */
  clearResponseQueue(): void {
    this.responseQueue = [];
  }

  /**
   * Reset the server to its initial state.
   */
  reset(): void {
    this.clearRequests();
    this.clearResponseQueue();
    this.defaultResponse = {
      statusCode: 200,
      body: { success: true },
    };
  }

  /**
   * Handle incoming HTTP request.
   */
  private async handleRequest(
    req: IncomingMessage,
    res: ServerResponse
  ): Promise<void> {
    // Collect request body
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    const body = Buffer.concat(chunks).toString('utf-8');

    // Record the request
    this.requests.push({
      method: req.method || 'GET',
      url: req.url || '/',
      headers: { ...req.headers } as Record<string, string | string[] | undefined>,
      body,
      timestamp: Date.now(),
    });

    // Get response config (queued or default)
    const responseConfig = this.responseQueue.shift() || this.defaultResponse;

    // Apply delay if specified
    if (responseConfig.delay && responseConfig.delay > 0) {
      await new Promise((resolve) => setTimeout(resolve, responseConfig.delay));
    }

    // Send response
    const responseBody =
      typeof responseConfig.body === 'string'
        ? responseConfig.body
        : JSON.stringify(responseConfig.body);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...responseConfig.headers,
    };

    res.writeHead(responseConfig.statusCode, headers);
    res.end(responseBody);
  }
}

/**
 * Create responses for simulating retry scenarios.
 * Returns N failures followed by a success.
 */
export function createRetryScenario(
  failureCount: number,
  failureStatus: number = 500,
  successBody: object = { success: true }
): ResponseConfig[] {
  const responses: ResponseConfig[] = [];

  for (let i = 0; i < failureCount; i++) {
    responses.push({
      statusCode: failureStatus,
      body: { error: `Failure ${i + 1}/${failureCount}` },
    });
  }

  responses.push({
    statusCode: 200,
    body: successBody,
  });

  return responses;
}

/**
 * Create a Splunk HEC response.
 * Note: Splunk HEC returns 200 OK even for some errors,
 * with the error code in the JSON body.
 */
export function createSplunkHecResponse(
  code: number = 0,
  text: string = 'Success'
): ResponseConfig {
  // HEC returns 200 for most responses, error code is in the body
  return {
    statusCode: 200,
    body: { code, text },
  };
}

/**
 * Create a Datadog validate response.
 */
export function createDatadogValidateResponse(valid: boolean): ResponseConfig {
  return {
    statusCode: valid ? 200 : 403,
    body: { valid },
  };
}
