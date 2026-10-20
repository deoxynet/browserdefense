/**
 * BrowserDefense API Router
 *
 * Single Cloudflare Worker that routes to different handlers:
 * - POST /webhook/stripe -> Stripe webhook handler
 * - POST /checkout/create-session -> Create checkout session
 * - POST /forensics/{org_id} -> Receive encrypted forensics
 * - GET  /forensics/{org_id} -> List forensics for org
 * - GET  /forensics/{org_id}/{id} -> Retrieve specific forensic
 */

import stripeWebhook from './stripe-webhook';
import createCheckoutSession from './create-checkout-session';
import forensics, { ForensicsEnv } from './forensics';

export interface Env extends ForensicsEnv {
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  ENVIRONMENT: string;
  LICENSES: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // Route to appropriate handler
    if (path === '/webhook/stripe' || path === '/webhook/stripe/') {
      return stripeWebhook.fetch(request, env);
    }
    
    if (path === '/checkout/create-session' || path === '/api/create-checkout-session') {
      return createCheckoutSession.fetch(request, env);
    }

    // Route forensics endpoints: /forensics/{org_id}, /forensics/{org_id}/{id}
    if (path.startsWith('/forensics/')) {
      return forensics.fetch(request, env);
    }
    
    // Health check endpoint
    if (path === '/health' || path === '/') {
      return new Response(JSON.stringify({
        status: 'ok',
        service: 'browserdefense-api',
        environment: env.ENVIRONMENT,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    
    // 404 for unknown routes
    return new Response(JSON.stringify({
      error: 'not_found',
      message: 'Unknown endpoint: ' + path,
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
