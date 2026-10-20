/**
 * Stripe Webhook Handler for BrowserDefense
 *
 * Cloudflare Worker that handles Stripe webhook events:
 * - checkout.session.completed: Generate license key and notify customer
 * - customer.subscription.deleted: Revoke access
 * - invoice.payment_failed: Notify customer
 */

export interface Env {
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  ENVIRONMENT: string;
  // KV namespace for license storage
  LICENSES: KVNamespace;
  // Email service configuration
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
}

interface StripeEvent {
  id: string;
  type: string;
  data: {
    object: Record<string, unknown>;
  };
}

interface CheckoutSession {
  id: string;
  customer: string;
  customer_email: string;
  subscription?: string;
  payment_status: string;
  metadata: Record<string, string>;
  line_items?: {
    data: Array<{
      price: {
        id: string;
        product: string;
      };
    }>;
  };
}

interface Subscription {
  id: string;
  customer: string;
  status: string;
  metadata: Record<string, string>;
}

interface Invoice {
  id: string;
  customer: string;
  customer_email: string;
  subscription?: string;
  status: string;
}

interface LicenseRecord {
  licenseKey: string;
  customerId: string;
  customerEmail: string;
  subscriptionId: string | null;
  tier: string;
  status: 'active' | 'revoked' | 'expired' | 'payment_failed';
  createdAt: string;
  updatedAt: string;
  revokedAt?: string;
}

/**
 * Generate a license key for a customer
 * Format: BIOC-XXXX-XXXX-XXXX-XXXX
 */
function generateLicenseKey(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments: string[] = [];

  for (let s = 0; s < 4; s++) {
    let segment = '';
    for (let i = 0; i < 4; i++) {
      const randomIndex = Math.floor(Math.random() * chars.length);
      segment += chars[randomIndex];
    }
    segments.push(segment);
  }

  return 'BIOC-' + segments.join('-');
}

/**
 * Verify Stripe webhook signature using Web Crypto API
 * Stripe uses HMAC-SHA256 for webhook signatures
 */
async function verifyStripeSignature(
  payload: string,
  signature: string,
  secret: string,
): Promise<boolean> {
  const parts = signature.split(',');
  const timestamp = parts.find((p) => p.startsWith('t='))?.substring(2);
  const v1Signature = parts.find((p) => p.startsWith('v1='))?.substring(3);

  if (!timestamp || !v1Signature) {
    return false;
  }

  // Check timestamp to prevent replay attacks (5 minute tolerance)
  const now = Math.floor(Date.now() / 1000);
  const eventTime = parseInt(timestamp, 10);
  if (Math.abs(now - eventTime) > 300) {
    return false;
  }

  // Compute expected signature
  const signedPayload = timestamp + '.' + payload;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(signedPayload),
  );

  const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Constant-time comparison
  return timingSafeEqual(expectedSignature, v1Signature);
}

/**
 * Constant-time string comparison to prevent timing attacks
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Store license key in KV
 * Creates multiple indexes for lookup by license key, customer, and subscription
 */
async function storeLicense(
  env: Env,
  license: LicenseRecord,
): Promise<void> {
  const expirationTtl = 60 * 60 * 24 * 365 * 2; // 2 years

  // Store by license key (primary)
  await env.LICENSES.put(
    `license:${license.licenseKey}`,
    JSON.stringify(license),
    { expirationTtl },
  );

  // Index by customer ID
  await env.LICENSES.put(
    `customer:${license.customerId}:license`,
    license.licenseKey,
    { expirationTtl },
  );

  // Index by subscription ID (if exists)
  if (license.subscriptionId) {
    await env.LICENSES.put(
      `subscription:${license.subscriptionId}:license`,
      license.licenseKey,
      { expirationTtl },
    );
  }

  // Index by email
  await env.LICENSES.put(
    `email:${license.customerEmail}:license`,
    license.licenseKey,
    { expirationTtl },
  );
}

/**
 * Get license by subscription ID
 */
async function getLicenseBySubscription(
  env: Env,
  subscriptionId: string,
): Promise<LicenseRecord | null> {
  const licenseKey = await env.LICENSES.get(
    `subscription:${subscriptionId}:license`,
  );
  if (!licenseKey) {
    return null;
  }

  const licenseJson = await env.LICENSES.get(`license:${licenseKey}`);
  if (!licenseJson) {
    return null;
  }

  return JSON.parse(licenseJson) as LicenseRecord;
}

/**
 * Get license by customer ID
 */
async function getLicenseByCustomer(
  env: Env,
  customerId: string,
): Promise<LicenseRecord | null> {
  const licenseKey = await env.LICENSES.get(`customer:${customerId}:license`);
  if (!licenseKey) {
    return null;
  }

  const licenseJson = await env.LICENSES.get(`license:${licenseKey}`);
  if (!licenseJson) {
    return null;
  }

  return JSON.parse(licenseJson) as LicenseRecord;
}

/**
 * Update license status
 */
async function updateLicenseStatus(
  env: Env,
  licenseKey: string,
  status: LicenseRecord['status'],
  additionalFields?: Partial<LicenseRecord>,
): Promise<void> {
  const licenseJson = await env.LICENSES.get(`license:${licenseKey}`);
  if (!licenseJson) {
    console.error('[BrowserDefense] License not found: ' + licenseKey);
    return;
  }

  const license = JSON.parse(licenseJson) as LicenseRecord;
  const updatedLicense: LicenseRecord = {
    ...license,
    ...additionalFields,
    status,
    updatedAt: new Date().toISOString(),
  };

  await env.LICENSES.put(
    `license:${licenseKey}`,
    JSON.stringify(updatedLicense),
  );
}

/**
 * Send email notification via Resend API
 */
async function sendEmail(
  env: Env,
  to: string,
  subject: string,
  html: string,
): Promise<boolean> {
  if (!env.RESEND_API_KEY) {
    console.log('[BrowserDefense] Email skipped - RESEND_API_KEY not configured');
    console.log('[BrowserDefense] Would send to: ' + to);
    console.log('[BrowserDefense] Subject: ' + subject);
    return true;
  }

  const fromEmail = env.EMAIL_FROM || 'BrowserDefense <noreply@blockioc.com>';

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [to],
        subject,
        html,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('[BrowserDefense] Email send failed: ' + error);
      return false;
    }

    console.log('[BrowserDefense] Email sent to ' + to);
    return true;
  } catch (err) {
    console.error('[BrowserDefense] Email error: ' + (err as Error).message);
    return false;
  }
}

/**
 * Send welcome email with license key
 */
async function sendWelcomeEmail(
  env: Env,
  email: string,
  licenseKey: string,
  tier: string,
): Promise<boolean> {
  const tierName = tier.charAt(0).toUpperCase() + tier.slice(1);

  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #1a1a2e; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }
    .license-box { background: white; border: 2px solid #1a1a2e; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }
    .license-key { font-family: 'Courier New', monospace; font-size: 24px; font-weight: bold; color: #1a1a2e; letter-spacing: 2px; }
    .button { display: inline-block; background: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 20px; }
    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Welcome to BrowserDefense ${tierName}!</h1>
    </div>
    <div class="content">
      <p>Thank you for subscribing to BrowserDefense ${tierName}. Your browser-based threat protection is now active.</p>

      <div class="license-box">
        <p style="margin: 0 0 10px 0; color: #666;">Your License Key</p>
        <div class="license-key">${licenseKey}</div>
      </div>

      <p><strong>Next Steps:</strong></p>
      <ol>
        <li>Install the BrowserDefense Chrome extension from the Chrome Web Store</li>
        <li>Enter your license key when prompted</li>
        <li>Your team is now protected against phishing and malicious URLs</li>
      </ol>

      <p>Need help? Reply to this email or visit our documentation at docs.blockioc.com</p>

      <a href="https://blockioc.com/docs/getting-started" class="button">Get Started Guide</a>
    </div>
    <div class="footer">
      <p>BrowserDefense - Browser-based IOC Blocking</p>
      <p>© ${new Date().getFullYear()} BrowserDefense. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
`;

  return sendEmail(
    env,
    email,
    `Welcome to BrowserDefense ${tierName} - Your License Key`,
    html,
  );
}

/**
 * Send subscription cancelled email
 */
async function sendCancellationEmail(
  env: Env,
  email: string,
): Promise<boolean> {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #1a1a2e; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }
    .button { display: inline-block; background: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 20px; }
    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Subscription Cancelled</h1>
    </div>
    <div class="content">
      <p>We're sorry to see you go. Your BrowserDefense subscription has been cancelled.</p>

      <p>Your license key has been deactivated and the browser extension will no longer receive blocklist updates.</p>

      <p>If you cancelled by mistake or would like to resubscribe, you can do so at any time:</p>

      <a href="https://blockioc.com/pricing" class="button">Resubscribe</a>

      <p style="margin-top: 30px;">We'd love to hear your feedback on why you cancelled. Reply to this email to let us know how we can improve.</p>
    </div>
    <div class="footer">
      <p>BrowserDefense - Browser-based IOC Blocking</p>
      <p>© ${new Date().getFullYear()} BrowserDefense. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
`;

  return sendEmail(env, email, 'Your BrowserDefense Subscription Has Been Cancelled', html);
}

/**
 * Send payment failed email
 */
async function sendPaymentFailedEmail(
  env: Env,
  email: string,
): Promise<boolean> {
  const html = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
    .header { background: #dc2626; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }
    .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 8px 8px; }
    .button { display: inline-block; background: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 20px; }
    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Payment Failed</h1>
    </div>
    <div class="content">
      <p>We were unable to process your payment for BrowserDefense.</p>

      <p>Please update your payment method to continue enjoying uninterrupted protection:</p>

      <a href="https://blockioc.com/account/billing" class="button">Update Payment Method</a>

      <p style="margin-top: 30px;"><strong>What happens next?</strong></p>
      <ul>
        <li>We'll retry the payment in a few days</li>
        <li>If payment continues to fail, your subscription may be cancelled</li>
        <li>Your protection remains active during the retry period</li>
      </ul>

      <p>If you need assistance, please reply to this email.</p>
    </div>
    <div class="footer">
      <p>BrowserDefense - Browser-based IOC Blocking</p>
      <p>© ${new Date().getFullYear()} BrowserDefense. All rights reserved.</p>
    </div>
  </div>
</body>
</html>
`;

  return sendEmail(env, email, 'Action Required: Payment Failed for BrowserDefense', html);
}

/**
 * Handle checkout.session.completed event
 * Generate license key and store customer info
 */
async function handleCheckoutCompleted(
  session: CheckoutSession,
  env: Env,
): Promise<Response> {
  const licenseKey = generateLicenseKey();
  const customerEmail = session.customer_email;

  // Determine tier from product/price
  let tier = 'team';
  if (session.metadata?.tier) {
    tier = session.metadata.tier;
  }

  console.log('[BrowserDefense] New ' + tier + ' subscription for ' + customerEmail);
  console.log('[BrowserDefense] Generated license key: ' + licenseKey);

  // Create license record
  const license: LicenseRecord = {
    licenseKey,
    customerId: session.customer,
    customerEmail,
    subscriptionId: session.subscription || null,
    tier,
    status: 'active',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  // Store license key in KV
  await storeLicense(env, license);
  console.log('[BrowserDefense] License stored in KV');

  // Send welcome email with license key
  await sendWelcomeEmail(env, customerEmail, licenseKey, tier);

  return new Response(
    JSON.stringify({
      success: true,
      event: 'checkout.session.completed',
      customer_email: customerEmail,
      license_key: licenseKey,
      tier: tier,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

/**
 * Handle customer.subscription.deleted event
 * Revoke access for the customer
 */
async function handleSubscriptionDeleted(
  subscription: Subscription,
  env: Env,
): Promise<Response> {
  console.log('[BrowserDefense] Subscription ' + subscription.id + ' deleted');

  // Lookup license by subscription ID
  const license = await getLicenseBySubscription(env, subscription.id);

  if (license) {
    // Mark license as revoked
    await updateLicenseStatus(env, license.licenseKey, 'revoked', {
      revokedAt: new Date().toISOString(),
    });
    console.log('[BrowserDefense] License ' + license.licenseKey + ' revoked');

    // Send cancellation email
    await sendCancellationEmail(env, license.customerEmail);
  } else {
    // Try to find by customer ID as fallback
    const customerLicense = await getLicenseByCustomer(env, subscription.customer);
    if (customerLicense) {
      await updateLicenseStatus(env, customerLicense.licenseKey, 'revoked', {
        revokedAt: new Date().toISOString(),
      });
      console.log('[BrowserDefense] License ' + customerLicense.licenseKey + ' revoked (by customer lookup)');
      await sendCancellationEmail(env, customerLicense.customerEmail);
    } else {
      console.warn('[BrowserDefense] No license found for subscription ' + subscription.id);
    }
  }

  return new Response(
    JSON.stringify({
      success: true,
      event: 'customer.subscription.deleted',
      subscription_id: subscription.id,
      customer: subscription.customer,
      license_revoked: !!license,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

/**
 * Handle invoice.payment_failed event
 * Notify customer of payment issue
 */
async function handlePaymentFailed(
  invoice: Invoice,
  env: Env,
): Promise<Response> {
  console.log('[BrowserDefense] Payment failed for invoice ' + invoice.id);

  // Update subscription status if we have a subscription ID
  if (invoice.subscription) {
    const license = await getLicenseBySubscription(env, invoice.subscription);
    if (license) {
      await updateLicenseStatus(env, license.licenseKey, 'payment_failed');
      console.log('[BrowserDefense] License ' + license.licenseKey + ' marked as payment_failed');
    }
  }

  // Send notification email to customer
  if (invoice.customer_email) {
    await sendPaymentFailedEmail(env, invoice.customer_email);
  }

  return new Response(
    JSON.stringify({
      success: true,
      event: 'invoice.payment_failed',
      invoice_id: invoice.id,
      customer_email: invoice.customer_email,
    }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Only accept POST requests
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    // Get the stripe signature header
    const signature = request.headers.get('stripe-signature');
    if (!signature) {
      return new Response('Missing stripe-signature header', { status: 400 });
    }

    // Get the raw body
    const payload = await request.text();

    // Verify the webhook signature
    const isValid = await verifyStripeSignature(
      payload,
      signature,
      env.STRIPE_WEBHOOK_SECRET,
    );

    if (!isValid) {
      console.error('[BrowserDefense] Invalid webhook signature');
      return new Response('Invalid signature', { status: 401 });
    }

    // Parse the event
    let event: StripeEvent;
    try {
      event = JSON.parse(payload);
    } catch {
      return new Response('Invalid JSON payload', { status: 400 });
    }

    console.log('[BrowserDefense] Received event: ' + event.type);

    // Handle the event
    switch (event.type) {
      case 'checkout.session.completed':
        return handleCheckoutCompleted(
          event.data.object as unknown as CheckoutSession,
          env,
        );

      case 'customer.subscription.deleted':
        return handleSubscriptionDeleted(
          event.data.object as unknown as Subscription,
          env,
        );

      case 'invoice.payment_failed':
        return handlePaymentFailed(
          event.data.object as unknown as Invoice,
          env,
        );

      default:
        // Acknowledge unhandled events
        console.log('[BrowserDefense] Unhandled event type: ' + event.type);
        return new Response(
          JSON.stringify({
            success: true,
            event: event.type,
            message: 'Event acknowledged but not processed',
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
    }
  },
};
