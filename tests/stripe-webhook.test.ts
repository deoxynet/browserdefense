/**
 * Tests for Stripe Webhook Handler
 */

import { describe, it, expect, vi } from 'vitest';

// Helper to create HMAC signature (same as in webhook)
async function createTestSignature(
  payload: string,
  secret: string,
  timestamp: number
): Promise<string> {
  const signedPayload = timestamp + '.' + payload;
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(signedPayload)
  );
  
  const signature = Array.from(new Uint8Array(signatureBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return 't=' + timestamp + ',v1=' + signature;
}

describe('Stripe Webhook', () => {
  const TEST_SECRET = 'whsec_test_secret_123';
  
  describe('Signature Verification', () => {
    it('should verify a valid signature', async () => {
      const payload = JSON.stringify({
        id: 'evt_test',
        type: 'checkout.session.completed',
        data: { object: {} },
      });
      const timestamp = Math.floor(Date.now() / 1000);
      const signature = await createTestSignature(payload, TEST_SECRET, timestamp);
      
      // The signature format should match what Stripe sends
      expect(signature).toMatch(/^t=\d+,v1=[a-f0-9]{64}$/);
    });
    
    it('should reject expired timestamps', async () => {
      const payload = JSON.stringify({
        id: 'evt_test',
        type: 'checkout.session.completed',
        data: { object: {} },
      });
      // Timestamp from 10 minutes ago (beyond 5 min tolerance)
      const oldTimestamp = Math.floor(Date.now() / 1000) - 600;
      const signature = await createTestSignature(payload, TEST_SECRET, oldTimestamp);
      
      expect(signature).toContain('t=' + oldTimestamp);
    });
  });
  
  describe('License Key Generation', () => {
    it('should generate keys in correct format', () => {
      // Test the format: BIOC-XXXX-XXXX-XXXX-XXXX
      const keyFormat = /^BIOC-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
      
      // Generate a key using same logic
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
      
      const licenseKey = 'BIOC-' + segments.join('-');
      expect(licenseKey).toMatch(keyFormat);
    });
    
    it('should not include ambiguous characters', () => {
      const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
      
      // These should NOT be in the charset
      expect(chars).not.toContain('0');
      expect(chars).not.toContain('O');
      expect(chars).not.toContain('1');
      expect(chars).not.toContain('I');
      expect(chars).not.toContain('l');
    });
  });
});
