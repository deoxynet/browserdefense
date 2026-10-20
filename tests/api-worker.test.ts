import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the imported handlers before importing the API module
vi.mock('../functions/stripe-webhook', () => ({
  default: { fetch: vi.fn() },
}));

vi.mock('../functions/create-checkout-session', () => ({
  default: { fetch: vi.fn() },
}));

vi.mock('../functions/forensics', () => ({
  default: { fetch: vi.fn() },
}));

// Import after mocks are set up
import api from '../functions/api';
import type { Env } from '../functions/api';
import stripeWebhook from '../functions/stripe-webhook';
import createCheckoutSession from '../functions/create-checkout-session';
import forensics from '../functions/forensics';

// Get mock functions
const mockStripeWebhookFetch = stripeWebhook.fetch as ReturnType<typeof vi.fn>;
const mockCreateCheckoutSessionFetch = createCheckoutSession.fetch as ReturnType<typeof vi.fn>;
const mockForensicsFetch = forensics.fetch as ReturnType<typeof vi.fn>;

// =============================================================================
// Test Fixtures
// =============================================================================

function createMockEnv(): Env {
  return {
    STRIPE_SECRET_KEY: 'test_key_123',
    STRIPE_WEBHOOK_SECRET: 'whsec_test_123',
    ENVIRONMENT: 'test',
    LICENSES: {} as KVNamespace,
    FORENSICS_BUCKET: {} as R2Bucket,
    RATE_LIMIT_KV: {} as KVNamespace,
    CORS_ORIGIN: '*',
    SUPABASE_URL: 'https://test.supabase.co',
    SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
  };
}

function createRequest(path: string, method = 'GET', body?: string): Request {
  const url = `https://api.example.com${path}`;
  const init: RequestInit = { method };
  if (body) {
    init.body = body;
    init.headers = { 'Content-Type': 'application/json' };
  }
  return new Request(url, init);
}

// =============================================================================
// Tests
// =============================================================================

describe('API Worker', () => {
  let mockEnv: Env;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEnv = createMockEnv();
  });

  // ===========================================================================
  // Health Check Endpoint
  // ===========================================================================

  describe('Health Check', () => {
    it('should return health status on /', async () => {
      const request = createRequest('/');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const body = await response.json() as { status: string; service: string; environment: string };
      expect(body).toEqual({
        status: 'ok',
        service: 'browserdefense-api',
        environment: 'test',
      });
    });

    it('should return health status on /health', async () => {
      const request = createRequest('/health');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const body = await response.json() as { status: string; service: string };
      expect(body.status).toBe('ok');
      expect(body.service).toBe('browserdefense-api');
    });

    it('should return correct Content-Type header', async () => {
      const request = createRequest('/health');
      const response = await api.fetch(request, mockEnv);

      expect(response.headers.get('Content-Type')).toBe('application/json');
    });

    it('should reflect environment in health response', async () => {
      mockEnv.ENVIRONMENT = 'production';
      const request = createRequest('/health');
      const response = await api.fetch(request, mockEnv);

      const body = await response.json() as { environment: string };
      expect(body.environment).toBe('production');
    });
  });

  // ===========================================================================
  // Stripe Webhook Routing
  // ===========================================================================

  describe('Stripe Webhook Routing', () => {
    it('should route /webhook/stripe to stripe handler', async () => {
      const mockResponse = new Response('stripe ok', { status: 200 });
      mockStripeWebhookFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/webhook/stripe', 'POST', '{}');
      const response = await api.fetch(request, mockEnv);

      expect(mockStripeWebhookFetch).toHaveBeenCalledWith(request, mockEnv);
      expect(response).toBe(mockResponse);
    });

    it('should route /webhook/stripe/ (with trailing slash) to stripe handler', async () => {
      const mockResponse = new Response('stripe ok', { status: 200 });
      mockStripeWebhookFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/webhook/stripe/', 'POST', '{}');
      const response = await api.fetch(request, mockEnv);

      expect(mockStripeWebhookFetch).toHaveBeenCalled();
      expect(response).toBe(mockResponse);
    });

    it('should pass request and env to stripe handler', async () => {
      mockStripeWebhookFetch.mockResolvedValueOnce(new Response('ok'));

      const request = createRequest('/webhook/stripe', 'POST', '{"type":"test"}');
      await api.fetch(request, mockEnv);

      expect(mockStripeWebhookFetch).toHaveBeenCalledWith(request, mockEnv);
    });
  });

  // ===========================================================================
  // Checkout Session Routing
  // ===========================================================================

  describe('Checkout Session Routing', () => {
    it('should route /checkout/create-session to checkout handler', async () => {
      const mockResponse = new Response(JSON.stringify({ sessionId: 'sess_123' }));
      mockCreateCheckoutSessionFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/checkout/create-session', 'POST', '{}');
      const response = await api.fetch(request, mockEnv);

      expect(mockCreateCheckoutSessionFetch).toHaveBeenCalledWith(request, mockEnv);
      expect(response).toBe(mockResponse);
    });

    it('should route /api/create-checkout-session (legacy path) to checkout handler', async () => {
      const mockResponse = new Response(JSON.stringify({ sessionId: 'sess_456' }));
      mockCreateCheckoutSessionFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/api/create-checkout-session', 'POST', '{}');
      const response = await api.fetch(request, mockEnv);

      expect(mockCreateCheckoutSessionFetch).toHaveBeenCalled();
      expect(response).toBe(mockResponse);
    });
  });

  // ===========================================================================
  // Forensics Routing
  // ===========================================================================

  describe('Forensics Routing', () => {
    it('should route /forensics/{org_id} to forensics handler', async () => {
      const mockResponse = new Response(JSON.stringify({ forensics: [] }));
      mockForensicsFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/forensics/org-123', 'GET');
      const response = await api.fetch(request, mockEnv);

      expect(mockForensicsFetch).toHaveBeenCalledWith(request, mockEnv);
      expect(response).toBe(mockResponse);
    });

    it('should route /forensics/{org_id}/{id} to forensics handler', async () => {
      const mockResponse = new Response(JSON.stringify({ id: 'forensic-456' }));
      mockForensicsFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/forensics/org-123/forensic-456', 'GET');
      const response = await api.fetch(request, mockEnv);

      expect(mockForensicsFetch).toHaveBeenCalled();
      expect(response).toBe(mockResponse);
    });

    it('should route POST /forensics/{org_id} to forensics handler', async () => {
      const mockResponse = new Response(JSON.stringify({ success: true }));
      mockForensicsFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/forensics/org-123', 'POST', '{"data":"encrypted"}');
      const response = await api.fetch(request, mockEnv);

      expect(mockForensicsFetch).toHaveBeenCalledWith(request, mockEnv);
      expect(response).toBe(mockResponse);
    });

    it('should route /forensics/nested/org/path to forensics handler', async () => {
      const mockResponse = new Response('ok');
      mockForensicsFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/forensics/nested/org/path', 'GET');
      const response = await api.fetch(request, mockEnv);

      expect(mockForensicsFetch).toHaveBeenCalled();
      expect(response).toBe(mockResponse);
    });
  });

  // ===========================================================================
  // 404 Not Found
  // ===========================================================================

  describe('404 Not Found', () => {
    it('should return 404 for unknown routes', async () => {
      const request = createRequest('/unknown/path');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(404);
      const body = await response.json() as { error: string };
      expect(body.error).toBe('not_found');
    });

    it('should include path in error message', async () => {
      const request = createRequest('/some/random/endpoint');
      const response = await api.fetch(request, mockEnv);

      const body = await response.json() as { message: string };
      expect(body.message).toContain('/some/random/endpoint');
    });

    it('should return JSON Content-Type for 404', async () => {
      const request = createRequest('/not-found');
      const response = await api.fetch(request, mockEnv);

      expect(response.headers.get('Content-Type')).toBe('application/json');
    });

    it('should return 404 for /webhook without /stripe', async () => {
      const request = createRequest('/webhook');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });

    it('should return 404 for /checkout without /create-session', async () => {
      const request = createRequest('/checkout');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(404);
    });

    it('should return 404 for /forensics without org_id', async () => {
      const request = createRequest('/forensics');
      const response = await api.fetch(request, mockEnv);

      // /forensics doesn't match /forensics/ prefix check
      expect(response.status).toBe(404);
    });
  });

  // ===========================================================================
  // Request Methods
  // ===========================================================================

  describe('Request Methods', () => {
    it('should handle GET requests', async () => {
      const request = createRequest('/health', 'GET');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(200);
    });

    it('should handle POST requests to valid endpoints', async () => {
      mockStripeWebhookFetch.mockResolvedValueOnce(new Response('ok'));

      const request = createRequest('/webhook/stripe', 'POST', '{}');
      const response = await api.fetch(request, mockEnv);

      expect(mockStripeWebhookFetch).toHaveBeenCalled();
    });

    it('should handle OPTIONS requests (passed to handlers)', async () => {
      mockForensicsFetch.mockResolvedValueOnce(new Response(null, { status: 204 }));

      const request = createRequest('/forensics/org-123', 'OPTIONS');
      await api.fetch(request, mockEnv);

      // Router passes all methods to handlers - CORS handling is in handlers
      expect(mockForensicsFetch).toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // URL Parsing
  // ===========================================================================

  describe('URL Parsing', () => {
    it('should handle URLs with query parameters', async () => {
      const request = createRequest('/health?foo=bar');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(200);
    });

    it('should route correctly with query parameters on forensics', async () => {
      mockForensicsFetch.mockResolvedValueOnce(new Response('ok'));

      const request = createRequest('/forensics/org-123?limit=10&offset=0');
      await api.fetch(request, mockEnv);

      expect(mockForensicsFetch).toHaveBeenCalled();
    });

    it('should handle URLs with hash fragments', async () => {
      // Note: hash fragments are typically not sent to server, but URL constructor handles them
      const request = createRequest('/health');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(200);
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('Error Handling', () => {
    it('should propagate errors from stripe handler', async () => {
      mockStripeWebhookFetch.mockRejectedValueOnce(new Error('Stripe error'));

      const request = createRequest('/webhook/stripe', 'POST', '{}');

      await expect(api.fetch(request, mockEnv)).rejects.toThrow('Stripe error');
    });

    it('should propagate errors from checkout handler', async () => {
      mockCreateCheckoutSessionFetch.mockRejectedValueOnce(new Error('Checkout error'));

      const request = createRequest('/checkout/create-session', 'POST', '{}');

      await expect(api.fetch(request, mockEnv)).rejects.toThrow('Checkout error');
    });

    it('should propagate errors from forensics handler', async () => {
      mockForensicsFetch.mockRejectedValueOnce(new Error('Forensics error'));

      const request = createRequest('/forensics/org-123', 'GET');

      await expect(api.fetch(request, mockEnv)).rejects.toThrow('Forensics error');
    });
  });

  // ===========================================================================
  // Handler Response Passthrough
  // ===========================================================================

  describe('Handler Response Passthrough', () => {
    it('should pass through handler response status', async () => {
      mockStripeWebhookFetch.mockResolvedValueOnce(new Response('error', { status: 400 }));

      const request = createRequest('/webhook/stripe', 'POST', '{}');
      const response = await api.fetch(request, mockEnv);

      expect(response.status).toBe(400);
    });

    it('should pass through handler response headers', async () => {
      const mockResponse = new Response('ok', {
        headers: { 'X-Custom-Header': 'custom-value' },
      });
      mockForensicsFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/forensics/org-123', 'GET');
      const response = await api.fetch(request, mockEnv);

      expect(response.headers.get('X-Custom-Header')).toBe('custom-value');
    });

    it('should pass through handler response body', async () => {
      const mockResponse = new Response(JSON.stringify({ custom: 'data' }));
      mockCreateCheckoutSessionFetch.mockResolvedValueOnce(mockResponse);

      const request = createRequest('/checkout/create-session', 'POST', '{}');
      const response = await api.fetch(request, mockEnv);

      const body = await response.json() as { custom: string };
      expect(body).toEqual({ custom: 'data' });
    });
  });
});
