/** HTML 转义，防止 PDF 导出 / 动态内容注入 XSS */
export function escapeHtml(text: string): string {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** 将 Markdown 文本安全转换为 HTML（先转义再应用格式） */
export function markdownToSafeHtml(raw: string): string {
  const escaped = escapeHtml(raw);
  return escaped
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br/>');
}

/** 从服务端用户资料中剥离敏感字段，供内存态 UI 使用。 */
export function sanitizeUserForStorage(user: any): any {
  if (!user || typeof user !== 'object') return user;
  const { ai_config, ...rest } = user;
  const safeAiConfig = ai_config
    ? {
        baseUrl: ai_config.baseUrl || ai_config.base_url || '',
        apiKey: '', // 永不持久化明文密钥
        apiKeyConfigured: Boolean(ai_config.apiKeyConfigured || ai_config.apiKey || ai_config.api_key),
        reportModel: ai_config.reportModel || ai_config.report_model || '',
        fastModel: ai_config.fastModel || ai_config.fast_model || '',
        strongModel: ai_config.strongModel || ai_config.strong_model || '',
      }
    : undefined;
  return { ...rest, ...(safeAiConfig ? { ai_config: safeAiConfig } : {}) };
}
