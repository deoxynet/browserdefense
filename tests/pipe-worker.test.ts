import { describe, it, expect, beforeEach, vi } from 'vitest';
import pipe from '../functions/pipe';
import type { PipeEnv } from '../functions/pipe';

// =============================================================================
// Test Fixtures
// =============================================================================

function createMockDurableObjectStub() {
  return {
    fetch: vi.fn().mockResolvedValue(new Response(JSON.stringify({ status: 'ok' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })),
  };
}

function createMockDurableObjectNamespace() {
  const mockStub = createMockDurableObjectStub();
  return {
    idFromName: vi.fn().mockReturnValue({ toString: () => 'mock-do-id' }),
    get: vi.fn().mockReturnValue(mockStub),
    _mockStub: mockStub,
  };
}

function createMockEnv(): PipeEnv & { PIPE_SESSIONS: ReturnType<typeof createMockDurableObjectNamespace> } {
  return {
    PIPE_SESSIONS: createMockDurableObjectNamespace() as unknown as DurableObjectNamespace,
    CORS_ORIGIN: '*',
    HEARTBEAT_INTERVAL_MS: '15000',
  } as PipeEnv & { PIPE_SESSIONS: ReturnType<typeof createMockDurableObjectNamespace> };
}

function createRequest(
  path: string,
  method = 'GET',
  body?: string,
  headers: Record<string, string> = {}
): Request {
  const url = `https://pipe.example.com${path}`;
  const init: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  };
  if (body !== undefined) {
    init.body = body;
  }
  return new Request(url, init);
}

// =============================================================================
// Tests
// =============================================================================

describe('Pipe Worker', () => {
  let mockEnv: ReturnType<typeof createMockEnv>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEnv = createMockEnv();
  });

  // ===========================================================================
  // CORS Handling
  // ===========================================================================

  describe('CORS Handling', () => {
    it('should handle OPTIONS preflight request', async () => {
      const request = createRequest('/stream?op_id=test123', 'OPTIONS');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('GET');
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST');
    });

    it('should use custom CORS_ORIGIN when set', async () => {
      mockEnv.CORS_ORIGIN = 'https://dashboard.example.com';
      const request = createRequest('/stream?op_id=test123', 'OPTIONS');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://dashboard.example.com');
    });

    it('should include CORS headers in all responses', async () => {
      const request = createRequest('/health');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    });
  });

  // ===========================================================================
  // Health Check
  // ===========================================================================

  describe('Health Check', () => {
    it('should return health status on /health', async () => {
      const request = createRequest('/health');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const body = await response.json() as { status: string; service: string };
      expect(body.status).toBe('ok');
      expect(body.service).toBe('pipe-server');
    });

    it('should return JSON content type', async () => {
      const request = createRequest('/health');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.headers.get('Content-Type')).toBe('application/json');
    });
  });

  // ===========================================================================
  // GET /stream
  // ===========================================================================

  describe('GET /stream', () => {
    it('should require op_id parameter', async () => {
      const request = createRequest('/stream');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('op_id');
    });

    it('should reject invalid op_id format (special chars)', async () => {
      const request = createRequest('/stream?op_id=test@invalid!');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Invalid op_id');
    });

    it('should reject op_id that is too long', async () => {
      const longOpId = 'a'.repeat(65);
      const request = createRequest(`/stream?op_id=${longOpId}`);
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Invalid op_id');
    });

    it('should accept valid op_id with alphanumeric and dashes', async () => {
      const request = createRequest('/stream?op_id=test-op_123');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS.idFromName).toHaveBeenCalledWith('test-op_123');
      expect(mockEnv.PIPE_SESSIONS.get).toHaveBeenCalled();
    });

    it('should forward request to Durable Object', async () => {
      const request = createRequest('/stream?op_id=test123');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS._mockStub.fetch).toHaveBeenCalled();
    });

    it('should include heartbeat interval header in DO request', async () => {
      mockEnv.HEARTBEAT_INTERVAL_MS = '30000';
      const request = createRequest('/stream?op_id=test123');
      await pipe.fetch(request, mockEnv);

      const doFetchCall = mockEnv.PIPE_SESSIONS._mockStub.fetch.mock.calls[0][0] as Request;
      expect(doFetchCall.headers.get('X-Heartbeat-Interval-Ms')).toBe('30000');
    });

    it('should use default heartbeat interval if not set', async () => {
      mockEnv.HEARTBEAT_INTERVAL_MS = '';
      const request = createRequest('/stream?op_id=test123');
      await pipe.fetch(request, mockEnv);

      const doFetchCall = mockEnv.PIPE_SESSIONS._mockStub.fetch.mock.calls[0][0] as Request;
      expect(doFetchCall.headers.get('X-Heartbeat-Interval-Ms')).toBe('15000');
    });
  });

  // ===========================================================================
  // POST /ack
  // ===========================================================================

  describe('POST /ack', () => {
    it('should require op_id parameter', async () => {
      const request = createRequest('/ack', 'POST', '{"message":"hello"}');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('op_id');
    });

    it('should reject invalid op_id format', async () => {
      const request = createRequest('/ack?op_id=test@invalid', 'POST', '{"message":"hello"}');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Invalid op_id');
    });

    it('should reject payload too large (Content-Length header)', async () => {
      const request = createRequest('/ack?op_id=test123', 'POST', '{}', {
        'Content-Length': '5000',
      });
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(413);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Payload too large');
    });

    it('should reject payload too large (actual body)', async () => {
      const largePayload = JSON.stringify({ data: 'x'.repeat(5000) });
      const request = createRequest('/ack?op_id=test123', 'POST', largePayload);
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(413);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Payload too large');
    });

    it('should reject invalid JSON body', async () => {
      const request = createRequest('/ack?op_id=test123', 'POST', 'not-valid-json');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Invalid JSON');
    });

    it('should reject non-object payload (string)', async () => {
      const request = createRequest('/ack?op_id=test123', 'POST', '"just a string"');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('must be an object');
    });

    it('should accept array payload (arrays are objects in JS)', async () => {
      // Arrays pass typeof === 'object' check, so they're forwarded to DO
      const request = createRequest('/ack?op_id=test123', 'POST', '[1,2,3]');
      const response = await pipe.fetch(request, mockEnv);

      // Should be forwarded to DO (200 from mock)
      expect(response.status).toBe(200);
    });

    it('should reject null payload', async () => {
      const request = createRequest('/ack?op_id=test123', 'POST', 'null');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('must be an object');
    });

    it('should forward valid ack to Durable Object', async () => {
      const payload = { message: 'hello', timestamp: 12345 };
      const request = createRequest('/ack?op_id=test123', 'POST', JSON.stringify(payload));
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS._mockStub.fetch).toHaveBeenCalled();
      const doFetchCall = mockEnv.PIPE_SESSIONS._mockStub.fetch.mock.calls[0][0] as Request;
      expect(doFetchCall.method).toBe('POST');
    });

    it('should return DO response with CORS headers', async () => {
      mockEnv.PIPE_SESSIONS._mockStub.fetch.mockResolvedValueOnce(
        new Response(JSON.stringify({ status: 'delivered', connections: 2 }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

      const request = createRequest('/ack?op_id=test123', 'POST', '{"data":"test"}');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
      const body = await response.json() as { status: string; connections: number };
      expect(body.status).toBe('delivered');
      expect(body.connections).toBe(2);
    });
  });

  // ===========================================================================
  // op_id Validation
  // ===========================================================================

  describe('op_id Validation', () => {
    it('should accept alphanumeric op_id', async () => {
      const request = createRequest('/stream?op_id=abc123');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS.idFromName).toHaveBeenCalledWith('abc123');
    });

    it('should accept op_id with underscores', async () => {
      const request = createRequest('/stream?op_id=test_op_id');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS.idFromName).toHaveBeenCalledWith('test_op_id');
    });

    it('should accept op_id with dashes', async () => {
      const request = createRequest('/stream?op_id=test-op-id');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS.idFromName).toHaveBeenCalledWith('test-op-id');
    });

    it('should accept max length op_id (64 chars)', async () => {
      const maxLengthOpId = 'a'.repeat(64);
      const request = createRequest(`/stream?op_id=${maxLengthOpId}`);
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS.idFromName).toHaveBeenCalledWith(maxLengthOpId);
    });

    it('should reject empty op_id', async () => {
      const request = createRequest('/stream?op_id=');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
    });

    it('should reject op_id with spaces', async () => {
      const request = createRequest('/stream?op_id=test%20space');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
    });

    it('should reject op_id with dots', async () => {
      const request = createRequest('/stream?op_id=test.dot');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(400);
    });
  });

  // ===========================================================================
  // 404 Not Found
  // ===========================================================================

  describe('404 Not Found', () => {
    it('should return 404 for unknown routes', async () => {
      const request = createRequest('/unknown/path');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(404);
      const body = await response.json() as { error: string };
      expect(body.error).toBe('Not found');
    });

    it('should return 404 for POST to /stream', async () => {
      const request = createRequest('/stream?op_id=test123', 'POST', '{}');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });

    it('should return 404 for GET to /ack', async () => {
      const request = createRequest('/ack?op_id=test123');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });

    it('should return 404 for POST to /health', async () => {
      const request = createRequest('/health', 'POST', '{}');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('Error Handling', () => {
    it('should return 500 on internal error', async () => {
      mockEnv.PIPE_SESSIONS.idFromName = vi.fn().mockImplementation(() => {
        throw new Error('DO namespace error');
      });
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const request = createRequest('/stream?op_id=test123');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.status).toBe(500);
      const body = await response.json() as { error: string };
      expect(body.error).toContain('Internal server error');
      expect(consoleSpy).toHaveBeenCalled();
    });

    it('should include CORS headers in error responses', async () => {
      mockEnv.PIPE_SESSIONS.idFromName = vi.fn().mockImplementation(() => {
        throw new Error('Some error');
      });
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const request = createRequest('/stream?op_id=test123');
      const response = await pipe.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    });
  });

  // ===========================================================================
  // Durable Object Integration
  // ===========================================================================

  describe('Durable Object Integration', () => {
    it('should create DO ID from op_id name', async () => {
      const request = createRequest('/stream?op_id=unique-op-id');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS.idFromName).toHaveBeenCalledWith('unique-op-id');
    });

    it('should get DO stub from namespace', async () => {
      const request = createRequest('/stream?op_id=test123');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS.get).toHaveBeenCalled();
    });

    it('should forward request to DO stub', async () => {
      const request = createRequest('/stream?op_id=test123');
      await pipe.fetch(request, mockEnv);

      expect(mockEnv.PIPE_SESSIONS._mockStub.fetch).toHaveBeenCalled();
    });

    it('should pass original request URL to DO for stream', async () => {
      const request = createRequest('/stream?op_id=test123');
      await pipe.fetch(request, mockEnv);

      const doFetchCall = mockEnv.PIPE_SESSIONS._mockStub.fetch.mock.calls[0][0] as Request;
      expect(doFetchCall.url).toContain('/stream');
      expect(doFetchCall.url).toContain('op_id=test123');
    });

    it('should pass original request URL to DO for ack', async () => {
      const request = createRequest('/ack?op_id=test123', 'POST', '{"data":"test"}');
      await pipe.fetch(request, mockEnv);

      const doFetchCall = mockEnv.PIPE_SESSIONS._mockStub.fetch.mock.calls[0][0] as Request;
      expect(doFetchCall.url).toContain('/ack');
      expect(doFetchCall.url).toContain('op_id=test123');
    });
  });
});
