/**
 * Create Checkout Session API
 * 
 * Cloudflare Worker that creates Stripe Checkout sessions.
 * Called by the website when user clicks "Buy Now".
 */

export interface Env {
  STRIPE_SECRET_KEY: string;
  ENVIRONMENT: string;
}

interface CreateSessionRequest {
  priceId: string;
  tier: string;
  successUrl: string;
  cancelUrl: string;
}

interface StripeCheckoutSession {
  id: string;
  url: string;
}

const STRIPE_API = 'https://api.stripe.com/v1';

/**
 * Create a Stripe Checkout Session via API
 */
async function createStripeSession(
  env: Env,
  priceId: string,
  tier: string,
  successUrl: string,
  cancelUrl: string
): Promise<StripeCheckoutSession> {
  const isSubscription = tier !== 'compliance';
  
  const params = new URLSearchParams({
    'mode': isSubscription ? 'subscription' : 'payment',
    'success_url': successUrl + '?session_id={CHECKOUT_SESSION_ID}',
    'cancel_url': cancelUrl,
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'metadata[tier]': tier,
    'metadata[source]': 'browserdefense-website',
  });
  
  // For subscriptions, allow promotion codes
  if (isSubscription) {
    params.append('allow_promotion_codes', 'true');
  }
  
  const response = await fetch(STRIPE_API + '/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + env.STRIPE_SECRET_KEY,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });
  
  if (!response.ok) {
    const error = await response.json();
    console.error('[BrowserDefense] Stripe API error:', error);
    throw new Error('Failed to create checkout session');
  }
  
  const session = await response.json() as StripeCheckoutSession;
  return session;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        },
      });
    }
    
    // Only accept POST requests
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }
    
    try {
      const body: CreateSessionRequest = await request.json();
      
      // Validate required fields
      if (!body.priceId || !body.tier || !body.successUrl || !body.cancelUrl) {
        return new Response(JSON.stringify({
          error: 'validation_error',
          message: 'Missing required fields: priceId, tier, successUrl, cancelUrl',
        }), {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }
      
      // Create Stripe Checkout session
      const session = await createStripeSession(
        env,
        body.priceId,
        body.tier,
        body.successUrl,
        body.cancelUrl
      );
      
      return new Response(JSON.stringify({
        sessionId: session.id,
        url: session.url,
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    } catch (err) {
      console.error('[BrowserDefense] Error creating checkout session:', err);
      return new Response(JSON.stringify({
        error: 'internal_error',
        message: 'Failed to create checkout session',
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }
  },
};
