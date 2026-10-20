/**
 * Dashboard Tests
 * Reference: Issue #280
 */

import { describe, it, expect } from 'vitest';
import {
  formatTimeAgo,
  truncateUrl,
  getSimilarityInfo,
  escapeHtml,
  type SimilarityInfo,
} from '../src/dashboard/helpers';

describe('Dashboard Helpers', () => {
  describe('formatTimeAgo', () => {
    it('formats recent timestamps as "now"', () => {
      const now = Date.now();
      expect(formatTimeAgo(now)).toBe('now');
      expect(formatTimeAgo(now - 30 * 1000)).toBe('now'); // 30 seconds ago
    });

    it('formats minutes ago', () => {
      const now = Date.now();
      expect(formatTimeAgo(now - 60 * 1000)).toBe('1m ago');
      expect(formatTimeAgo(now - 5 * 60 * 1000)).toBe('5m ago');
      expect(formatTimeAgo(now - 59 * 60 * 1000)).toBe('59m ago');
    });

    it('formats hours ago', () => {
      const now = Date.now();
      expect(formatTimeAgo(now - 60 * 60 * 1000)).toBe('1h ago');
      expect(formatTimeAgo(now - 5 * 60 * 60 * 1000)).toBe('5h ago');
      expect(formatTimeAgo(now - 23 * 60 * 60 * 1000)).toBe('23h ago');
    });

    it('formats days ago', () => {
      const now = Date.now();
      expect(formatTimeAgo(now - 24 * 60 * 60 * 1000)).toBe('1d ago');
      expect(formatTimeAgo(now - 7 * 24 * 60 * 60 * 1000)).toBe('7d ago');
    });
  });

  describe('truncateUrl', () => {
    it('truncates long URLs', () => {
      const longUrl = 'https://example.com/very/long/path/that/exceeds/the/limit';
      const result = truncateUrl(longUrl);
      expect(result.length).toBeLessThanOrEqual(40);
      expect(result).toContain('example.com');
      expect(result).toContain('...');
    });

    it('preserves short URLs', () => {
      const shortUrl = 'https://example.com/short';
      const result = truncateUrl(shortUrl);
      expect(result).toBe('example.com/short');
    });

    it('handles invalid URLs gracefully', () => {
      const invalid = 'not-a-valid-url';
      const result = truncateUrl(invalid);
      expect(result).toBe('not-a-valid-url');
    });

    it('handles very long invalid URLs', () => {
      const longInvalid = 'x'.repeat(100);
      const result = truncateUrl(longInvalid);
      expect(result.length).toBeLessThanOrEqual(53);
      expect(result).toContain('...');
    });
  });

  describe('getSimilarityInfo', () => {
    it('marks null scores as new/unknown', () => {
      const result = getSimilarityInfo(null);
      expect(result).toEqual({
        percent: 0,
        level: 'unknown',
        isNew: true,
      });
    });

    it('categorizes high similarity (90%+)', () => {
      const result = getSimilarityInfo(0.95);
      expect(result).toEqual({
        percent: 95,
        level: 'high',
        isNew: false,
      });

      const result90 = getSimilarityInfo(0.90);
      expect(result90.level).toBe('high');
    });

    it('categorizes medium similarity (70-89%)', () => {
      const result = getSimilarityInfo(0.85);
      expect(result).toEqual({
        percent: 85,
        level: 'medium',
        isNew: false,
      });

      const result70 = getSimilarityInfo(0.70);
      expect(result70.level).toBe('medium');
    });

    it('categorizes low similarity (50-69%)', () => {
      const result = getSimilarityInfo(0.55);
      expect(result).toEqual({
        percent: 55,
        level: 'low',
        isNew: false,
      });

      const result50 = getSimilarityInfo(0.50);
      expect(result50.level).toBe('low');
    });

    it('marks very low scores as unknown/new', () => {
      const result = getSimilarityInfo(0.3);
      expect(result).toEqual({
        percent: 30,
        level: 'unknown',
        isNew: true,
      });
    });

    it('rounds percentages correctly', () => {
      const result = getSimilarityInfo(0.789);
      expect(result.percent).toBe(79);

      const result2 = getSimilarityInfo(0.991);
      expect(result2.percent).toBe(99);
    });
  });

  describe('escapeHtml', () => {
    it('escapes HTML special characters', () => {
      expect(escapeHtml('<script>alert("xss")</script>')).toBe(
        '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
      );
    });

    it('escapes ampersands', () => {
      expect(escapeHtml('foo & bar')).toBe('foo &amp; bar');
    });

    it('escapes quotes', () => {
      expect(escapeHtml('say "hello"')).toBe('say &quot;hello&quot;');
    });

    it('handles empty strings', () => {
      expect(escapeHtml('')).toBe('');
    });

    it('handles strings without special characters', () => {
      expect(escapeHtml('normal text')).toBe('normal text');
    });
  });
});

describe('Dashboard Data Types', () => {
  it('SimilarityInfo has correct shape', () => {
    const info: SimilarityInfo = {
      percent: 90,
      level: 'high',
      isNew: false,
    };
    expect(info.percent).toBeTypeOf('number');
    expect(['high', 'medium', 'low', 'unknown']).toContain(info.level);
    expect(info.isNew).toBeTypeOf('boolean');
  });
});
