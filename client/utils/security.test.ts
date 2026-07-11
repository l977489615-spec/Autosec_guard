import { describe, expect, it } from 'vitest';
import { escapeHtml, markdownToSafeHtml, sanitizeUserForStorage } from './security';

describe('browser security boundaries', () => {
  it('escapes executable markup before report formatting', () => {
    expect(markdownToSafeHtml('<img src=x onerror=alert(1)>')).not.toContain('<img');
    expect(escapeHtml('"<script>')).toBe('&quot;&lt;script&gt;');
  });

  it('never persists an AI API key', () => {
    const user = sanitizeUserForStorage({ username: 'operator', ai_config: { api_key: 'secret-value' } });
    expect(user.ai_config.apiKey).toBe('');
    expect(user.ai_config.apiKeyConfigured).toBe(true);
    expect(JSON.stringify(user)).not.toContain('secret-value');
  });
});
