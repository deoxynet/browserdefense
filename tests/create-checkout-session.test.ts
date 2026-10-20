import { describe, it, expect, beforeEach, vi } from 'vitest';
import createCheckoutSession from '../functions/create-checkout-session';
import type { Env } from '../functions/create-checkout-session';

// =============================================================================
// Test Fixtures
// =============================================================================

function createMockEnv(): Env {
  return {
    STRIPE_SECRET_KEY: 'test_key_123456789',
    ENVIRONMENT: 'test',
  };
}

function createValidRequestBody() {
  return {
    priceId: 'price_123ABC',
    tier: 'professional',
    successUrl: 'https://example.com/success',
    cancelUrl: 'https://example.com/cancel',
  };
}

function createRequest(
  method: string,
  body?: unknown,
  headers: Record<string, string> = {}
): Request {
  const url = 'https://api.example.com/checkout/create-session';
  const init: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  return new Request(url, init);
}

function mockStripeResponse(session: { id: string; url: string }) {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(session),
  };
}

function mockStripeErrorResponse(error: { error: { message: string } }) {
  return {
    ok: false,
    status: 400,
    json: () => Promise.resolve(error),
  };
}

// =============================================================================
// Tests
// =============================================================================

describe('Create Checkout Session', () => {
  let mockEnv: Env;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEnv = createMockEnv();
    mockFetch = vi.fn();
    global.fetch = mockFetch as typeof fetch;
  });

  // ===========================================================================
  // CORS Handling
  // ===========================================================================

  describe('CORS Handling', () => {
    it('should handle OPTIONS preflight request', async () => {
      const request = createRequest('OPTIONS');
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(204);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST');
      expect(response.headers.get('Access-Control-Allow-Headers')).toContain('Content-Type');
    });

    it('should include Max-Age header in preflight response', async () => {
      const request = createRequest('OPTIONS');
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Max-Age')).toBe('86400');
    });

    it('should include CORS headers in success response', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    });

    it('should include CORS headers in error response', async () => {
      const request = createRequest('POST', {});
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*');
    });
  });

  // ===========================================================================
  // HTTP Method Handling
  // ===========================================================================

  describe('HTTP Method Handling', () => {
    it('should reject GET requests', async () => {
      const request = createRequest('GET');
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(405);
    });

    it('should reject PUT requests', async () => {
      const request = createRequest('PUT', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(405);
    });

    it('should reject DELETE requests', async () => {
      const request = createRequest('DELETE');
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(405);
    });

    it('should accept POST requests', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(200);
    });
  });

  // ===========================================================================
  // Input Validation
  // ===========================================================================

  describe('Input Validation', () => {
    it('should reject request without priceId', async () => {
      const body = createValidRequestBody();
      delete (body as Partial<typeof body>).priceId;

      const request = createRequest('POST', body);
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const responseBody = await response.json() as { error: string; message: string };
      expect(responseBody.error).toBe('validation_error');
      expect(responseBody.message).toContain('priceId');
    });

    it('should reject request without tier', async () => {
      const body = createValidRequestBody();
      delete (body as Partial<typeof body>).tier;

      const request = createRequest('POST', body);
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const responseBody = await response.json() as { error: string; message: string };
      expect(responseBody.error).toBe('validation_error');
      expect(responseBody.message).toContain('tier');
    });

    it('should reject request without successUrl', async () => {
      const body = createValidRequestBody();
      delete (body as Partial<typeof body>).successUrl;

      const request = createRequest('POST', body);
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const responseBody = await response.json() as { error: string; message: string };
      expect(responseBody.error).toBe('validation_error');
      expect(responseBody.message).toContain('successUrl');
    });

    it('should reject request without cancelUrl', async () => {
      const body = createValidRequestBody();
      delete (body as Partial<typeof body>).cancelUrl;

      const request = createRequest('POST', body);
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const responseBody = await response.json() as { error: string; message: string };
      expect(responseBody.error).toBe('validation_error');
      expect(responseBody.message).toContain('cancelUrl');
    });

    it('should reject empty request body', async () => {
      const request = createRequest('POST', {});
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(400);
      const responseBody = await response.json() as { error: string };
      expect(responseBody.error).toBe('validation_error');
    });

    it('should reject invalid JSON body', async () => {
      const url = 'https://api.example.com/checkout/create-session';
      const request = new Request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not-valid-json',
      });
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(500);
    });
  });

  // ===========================================================================
  // Stripe Checkout Creation
  // ===========================================================================

  describe('Stripe Checkout Creation', () => {
    it('should create checkout session with valid request', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(200);
      const responseBody = await response.json() as { sessionId: string; url: string };
      expect(responseBody.sessionId).toBe('cs_test_123');
      expect(responseBody.url).toBe('https://checkout.stripe.com/session/123');
    });

    it('should call Stripe API with correct authorization', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      await createCheckoutSession.fetch(request, mockEnv);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('api.stripe.com'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test_key_123456789',
          }),
        })
      );
    });

    it('should call Stripe API with correct content type', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      await createCheckoutSession.fetch(request, mockEnv);

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded',
          }),
        })
      );
    });

    it('should append session_id to success URL', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('session_id');
      expect(callBody).toContain('CHECKOUT_SESSION_ID');
    });

    it('should include tier in metadata', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const body = createValidRequestBody();
      body.tier = 'enterprise';
      const request = createRequest('POST', body);
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('metadata%5Btier%5D=enterprise');
    });

    it('should include source in metadata', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('metadata%5Bsource%5D=browserdefense-website');
    });
  });

  // ===========================================================================
  // Subscription vs Payment Mode
  // ===========================================================================

  describe('Subscription vs Payment Mode', () => {
    it('should use subscription mode for non-compliance tiers', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const body = createValidRequestBody();
      body.tier = 'professional';
      const request = createRequest('POST', body);
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('mode=subscription');
    });

    it('should use payment mode for compliance tier', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const body = createValidRequestBody();
      body.tier = 'compliance';
      const request = createRequest('POST', body);
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('mode=payment');
    });

    it('should allow promotion codes for subscriptions', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const body = createValidRequestBody();
      body.tier = 'professional';
      const request = createRequest('POST', body);
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('allow_promotion_codes=true');
    });

    it('should not allow promotion codes for payment mode', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const body = createValidRequestBody();
      body.tier = 'compliance';
      const request = createRequest('POST', body);
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).not.toContain('allow_promotion_codes');
    });
  });

  // ===========================================================================
  // Error Handling
  // ===========================================================================

  describe('Error Handling', () => {
    it('should return 500 on Stripe API error', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeErrorResponse({
        error: { message: 'Invalid price ID' },
      }));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(500);
      const responseBody = await response.json() as { error: string; message: string };
      expect(responseBody.error).toBe('internal_error');
      expect(responseBody.message).toContain('Failed to create checkout session');
      expect(consoleSpy).toHaveBeenCalled();
    });

    it('should return 500 on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.status).toBe(500);
      expect(consoleSpy).toHaveBeenCalled();
    });

    it('should return JSON error response', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Some error'));
      vi.spyOn(console, 'error').mockImplementation(() => {});

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.headers.get('Content-Type')).toBe('application/json');
      const responseBody = await response.json() as { error: string };
      expect(responseBody.error).toBeDefined();
    });
  });

  // ===========================================================================
  // Response Format
  // ===========================================================================

  describe('Response Format', () => {
    it('should return sessionId and url on success', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_abc123',
        url: 'https://checkout.stripe.com/pay/cs_test_abc123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      const responseBody = await response.json() as { sessionId: string; url: string };
      expect(responseBody).toHaveProperty('sessionId');
      expect(responseBody).toHaveProperty('url');
      expect(responseBody.sessionId).toBe('cs_test_abc123');
      expect(responseBody.url).toContain('checkout.stripe.com');
    });

    it('should return Content-Type application/json', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      const response = await createCheckoutSession.fetch(request, mockEnv);

      expect(response.headers.get('Content-Type')).toBe('application/json');
    });
  });

  // ===========================================================================
  // Line Items
  // ===========================================================================

  describe('Line Items', () => {
    it('should include price ID in line items', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const body = createValidRequestBody();
      body.priceId = 'price_ABC123';
      const request = createRequest('POST', body);
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('line_items%5B0%5D%5Bprice%5D=price_ABC123');
    });

    it('should set quantity to 1', async () => {
      mockFetch.mockResolvedValueOnce(mockStripeResponse({
        id: 'cs_test_123',
        url: 'https://checkout.stripe.com/session/123',
      }));

      const request = createRequest('POST', createValidRequestBody());
      await createCheckoutSession.fetch(request, mockEnv);

      const callBody = mockFetch.mock.calls[0][1].body as string;
      expect(callBody).toContain('line_items%5B0%5D%5Bquantity%5D=1');
    });
  });
});
