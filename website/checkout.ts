/**
 * BrowserDefense Checkout Module
 * 
 * Handles Stripe Checkout integration for self-serve purchasing.
 * Redirects users to Stripe hosted checkout page.
 */

// Stripe product IDs (configure these in Stripe Dashboard)
export const PRODUCTS = {
  team: {
    priceId: 'price_team_annual', // Replace with actual Stripe price ID
    name: 'Team',
    amount: 2400,
    interval: 'year',
  },
  business: {
    priceId: 'price_business_annual', // Replace with actual Stripe price ID
    name: 'Business',
    amount: 6000,
    interval: 'year',
  },
  compliance: {
    priceId: 'price_compliance_onetime', // Replace with actual Stripe price ID
    name: 'Compliance Package',
    amount: 15000,
    interval: null, // One-time purchase
  },
} as const;

export type ProductTier = keyof typeof PRODUCTS;

interface CheckoutSessionResponse {
  sessionId: string;
  url: string;
}

interface CheckoutError {
  error: string;
  message: string;
}

/**
 * Configuration for checkout
 */
export interface CheckoutConfig {
  apiEndpoint: string; // Backend endpoint to create checkout sessions
  successUrl: string;  // URL to redirect after successful payment
  cancelUrl: string;   // URL to redirect if user cancels
}

const DEFAULT_CONFIG: CheckoutConfig = {
  apiEndpoint: '/api/create-checkout-session',
  successUrl: window.location.origin + '/success',
  cancelUrl: window.location.origin + '/pricing',
};

/**
 * Create a Stripe Checkout session and redirect to payment
 */
export async function startCheckout(
  tier: ProductTier,
  config: Partial<CheckoutConfig> = {}
): Promise<void> {
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  const product = PRODUCTS[tier];
  
  try {
    const response = await fetch(finalConfig.apiEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        priceId: product.priceId,
        tier: tier,
        successUrl: finalConfig.successUrl,
        cancelUrl: finalConfig.cancelUrl,
      }),
    });
    
    if (!response.ok) {
      const error: CheckoutError = await response.json();
      throw new Error(error.message || 'Failed to create checkout session');
    }
    
    const session: CheckoutSessionResponse = await response.json();
    
    // Redirect to Stripe Checkout
    window.location.href = session.url;
  } catch (err) {
    console.error('[BrowserDefense] Checkout error:', err);
    throw err;
  }
}

/**
 * Initialize checkout buttons on the page
 * Call this after DOM is ready
 */
export function initCheckoutButtons(): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>('[data-checkout-tier]');
  
  buttons.forEach(button => {
    const tier = button.dataset.checkoutTier as ProductTier;
    
    if (!PRODUCTS[tier]) {
      console.warn('[BrowserDefense] Unknown tier:', tier);
      return;
    }
    
    button.addEventListener('click', async (e) => {
      e.preventDefault();
      button.disabled = true;
      button.textContent = 'Redirecting...';
      
      try {
        await startCheckout(tier);
      } catch (err) {
        button.disabled = false;
        button.textContent = 'Try Again';
        alert('Failed to start checkout. Please try again.');
      }
    });
  });
}

/**
 * Check URL for success/cancel parameters
 * Call this on success page to show confirmation
 */
export function handleCheckoutResult(): { success: boolean; sessionId?: string } {
  const params = new URLSearchParams(window.location.search);
  const sessionId = params.get('session_id');
  
  if (sessionId) {
    return { success: true, sessionId };
  }
  
  return { success: false };
}

// Auto-initialize if DOM is ready
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCheckoutButtons);
  } else {
    initCheckoutButtons();
  }
}
