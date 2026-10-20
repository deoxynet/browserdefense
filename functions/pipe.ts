/**
 * BlockIOC Pipe Server Worker
 *
 * Stateful pass-through server that streams acks to analysts over SSE.
 * Uses Durable Objects to maintain per-op_id SSE connections.
 *
 * Architecture:
 *   Extension → POST /ack → Durable Object → SSE → Analyst Dashboard
 *                               ↑
 *                      GET /stream (opens SSE)
 *
 * Endpoints:
 *   GET  /stream?op_id=xxx  - Open SSE stream for receiving acks
 *   POST /ack?op_id=xxx     - Send ack payload to active stream
 *   GET  /health            - Health check
 *
 * Design:
 *   - Each op_id maps to a Durable Object instance
 *   - DO maintains active SSE connections and forwards acks
 *   - 15s heartbeat keeps connections alive
 *   - Disconnect cleans up resources
 *   - No persistent storage (in-memory only)
 *
 * Reference: Issue #402
 */

export interface PipeEnv {
  /** Durable Object namespace for pipe sessions */
  PIPE_SESSIONS: DurableObjectNamespace;
  /** CORS origin configuration */
  CORS_ORIGIN: string;
  /** Heartbeat interval in ms */
  HEARTBEAT_INTERVAL_MS: string;
}

/** Ack payload from extension */
interface AckPayload {
  /** Any JSON-serializable ack data */
  [key: string]: unknown;
}

// Validation
const OP_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;
const MAX_PAYLOAD_SIZE = 4096; // 4KB max for ack payloads

/**
 * Main worker fetch handler - routes requests to Durable Objects
 */
export default {
  async fetch(request: Request, env: PipeEnv): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': env.CORS_ORIGIN || '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Route: GET /stream?op_id=xxx
      if (path === '/stream' && request.method === 'GET') {
        return await handleStream(request, env, corsHeaders);
      }

      // Route: POST /ack?op_id=xxx
      if (path === '/ack' && request.method === 'POST') {
        return await handleAck(request, env, corsHeaders);
      }

      // Route: GET /health
      if (path === '/health' && request.method === 'GET') {
        return new Response(
          JSON.stringify({ status: 'ok', service: 'pipe-server' }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      return jsonError(404, 'Not found', corsHeaders);
    } catch (err) {
      console.error('Pipe server worker error:', err);
      return jsonError(500, 'Internal server error', corsHeaders);
    }
  },
};

/**
 * GET /stream - Open SSE stream for receiving acks
 */
async function handleStream(
  request: Request,
  env: PipeEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const url = new URL(request.url);
  const opId = url.searchParams.get('op_id');

  // Validate op_id
  if (!opId) {
    return jsonError(400, 'Missing op_id query parameter', corsHeaders);
  }
  if (!OP_ID_PATTERN.test(opId)) {
    return jsonError(400, 'Invalid op_id format', corsHeaders);
  }

  // Get Durable Object for this op_id
  const doId = env.PIPE_SESSIONS.idFromName(opId);
  const stub = env.PIPE_SESSIONS.get(doId);

  // Forward to DO with heartbeat interval
  const heartbeatMs = parseInt(env.HEARTBEAT_INTERVAL_MS || '15000', 10);
  const doRequest = new Request(request.url, {
    method: 'GET',
    headers: {
      ...Object.fromEntries(request.headers),
      'X-Heartbeat-Interval-Ms': String(heartbeatMs),
    },
  });

  return stub.fetch(doRequest);
}

/**
 * POST /ack - Send ack payload to active stream
 */
async function handleAck(
  request: Request,
  env: PipeEnv,
  corsHeaders: Record<string, string>
): Promise<Response> {
  const url = new URL(request.url);
  const opId = url.searchParams.get('op_id');

  // Validate op_id
  if (!opId) {
    return jsonError(400, 'Missing op_id query parameter', corsHeaders);
  }
  if (!OP_ID_PATTERN.test(opId)) {
    return jsonError(400, 'Invalid op_id format', corsHeaders);
  }

  // Check content length
  const contentLength = request.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength, 10) > MAX_PAYLOAD_SIZE) {
    return jsonError(413, `Payload too large. Maximum size is ${MAX_PAYLOAD_SIZE} bytes`, corsHeaders);
  }

  // Parse and validate payload
  let payload: AckPayload;
  try {
    const body = await request.text();
    if (body.length > MAX_PAYLOAD_SIZE) {
      return jsonError(413, `Payload too large. Maximum size is ${MAX_PAYLOAD_SIZE} bytes`, corsHeaders);
    }
    payload = JSON.parse(body);
  } catch {
    return jsonError(400, 'Invalid JSON body', corsHeaders);
  }

  if (typeof payload !== 'object' || payload === null) {
    return jsonError(400, 'Payload must be an object', corsHeaders);
  }

  // Get Durable Object for this op_id
  const doId = env.PIPE_SESSIONS.idFromName(opId);
  const stub = env.PIPE_SESSIONS.get(doId);

  // Forward ack to DO
  const doRequest = new Request(request.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const doResponse = await stub.fetch(doRequest);

  // Return response with CORS headers
  const responseBody = await doResponse.text();
  return new Response(responseBody, {
    status: doResponse.status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

/**
 * Return a JSON error response.
 */
function jsonError(
  status: number,
  message: string,
  corsHeaders: Record<string, string>
): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

/**
 * PipeSession Durable Object
 *
 * Maintains SSE connections for a single op_id and forwards acks.
 * Handles heartbeat and cleanup on disconnect.
 */
export class PipeSession {
  private state: DurableObjectState;
  private connections: Set<WritableStreamDefaultWriter<Uint8Array>>;
  private heartbeatInterval: ReturnType<typeof setInterval> | null;
  private encoder: TextEncoder;

  constructor(state: DurableObjectState) {
    this.state = state;
    this.connections = new Set();
    this.heartbeatInterval = null;
    this.encoder = new TextEncoder();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'GET' && url.pathname === '/stream') {
      return this.handleStreamConnection(request);
    }

    if (request.method === 'POST' && url.pathname === '/ack') {
      return this.handleAckDelivery(request);
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /**
   * Handle new SSE stream connection
   */
  private handleStreamConnection(request: Request): Response {
    const heartbeatMs = parseInt(
      request.headers.get('X-Heartbeat-Interval-Ms') || '15000',
      10
    );

    // Create SSE stream
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const writer = writable.getWriter();

    // Register this connection
    this.connections.add(writer);

    // Start heartbeat if this is first connection
    if (this.connections.size === 1) {
      this.startHeartbeat(heartbeatMs);
    }

    // Send initial connection event
    this.sendToWriter(writer, 'event: connected\ndata: {"status":"connected"}\n\n');

    console.log(`[PipeSession] Stream opened. Active connections: ${this.connections.size}`);

    // Set up cleanup on disconnect
    // We use waitUntil to ensure cleanup runs even after response completes
    this.state.waitUntil(
      (async () => {
        // Wait for the stream to close
        try {
          await writer.closed;
        } catch {
          // Writer closed with error (client disconnect)
        }

        // Cleanup
        this.connections.delete(writer);
        console.log(`[PipeSession] Stream closed. Active connections: ${this.connections.size}`);

        // Stop heartbeat if no more connections
        if (this.connections.size === 0) {
          this.stopHeartbeat();
        }
      })()
    );

    return new Response(readable, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
      },
    });
  }

  /**
   * Handle ack delivery to active streams
   */
  private async handleAckDelivery(request: Request): Promise<Response> {
    if (this.connections.size === 0) {
      return new Response(
        JSON.stringify({ status: 'no_active_streams' }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    const payload = await request.json();
    const sseData = `event: ack\ndata: ${JSON.stringify(payload)}\n\n`;

    // Send to all active connections
    let delivered = 0;
    const failedWriters: WritableStreamDefaultWriter<Uint8Array>[] = [];

    for (const writer of this.connections) {
      try {
        await this.sendToWriter(writer, sseData);
        delivered++;
      } catch {
        // Writer is closed, mark for cleanup
        failedWriters.push(writer);
      }
    }

    // Remove failed writers
    for (const writer of failedWriters) {
      this.connections.delete(writer);
    }

    console.log(`[PipeSession] Ack delivered to ${delivered}/${delivered + failedWriters.length} connections`);

    return new Response(
      JSON.stringify({
        status: 'delivered',
        connections: delivered,
      }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  /**
   * Send data to a single SSE writer
   */
  private async sendToWriter(
    writer: WritableStreamDefaultWriter<Uint8Array>,
    data: string
  ): Promise<void> {
    const chunk = this.encoder.encode(data);
    await writer.write(chunk);
  }

  /**
   * Start heartbeat interval to keep connections alive
   */
  private startHeartbeat(intervalMs: number): void {
    if (this.heartbeatInterval) return;

    this.heartbeatInterval = setInterval(async () => {
      const heartbeatData = `event: heartbeat\ndata: {"ts":${Date.now()}}\n\n`;
      const failedWriters: WritableStreamDefaultWriter<Uint8Array>[] = [];

      for (const writer of this.connections) {
        try {
          await this.sendToWriter(writer, heartbeatData);
        } catch {
          failedWriters.push(writer);
        }
      }

      // Remove failed writers
      for (const writer of failedWriters) {
        this.connections.delete(writer);
      }

      if (this.connections.size === 0) {
        this.stopHeartbeat();
      }
    }, intervalMs);

    console.log(`[PipeSession] Heartbeat started (${intervalMs}ms interval)`);
  }

  /**
   * Stop heartbeat interval
   */
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
      console.log('[PipeSession] Heartbeat stopped');
    }
  }
}
