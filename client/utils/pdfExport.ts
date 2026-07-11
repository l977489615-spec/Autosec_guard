export interface PdfExportOptions {
  filename: string;
  title: string;
  metadata: Array<{ label: string; value: string }>;
  reportHtml: string;
  appendixHtml?: string;
}

export interface MarkdownExportOptions {
  filename: string;
  title: string;
  metadata: Array<{ label: string; value: string }>;
  reportMarkdown: string;
}

const escape = (value: string) => value
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#039;');

const normalizedFilename = (filename: string, extension: string) => (
  filename.toLowerCase().endsWith(extension) ? filename : `${filename}${extension}`
);

/**
 * Open the browser's native PDF print pipeline in an invisible same-origin
 * frame. Unlike the previous html2canvas implementation, headings, paragraphs,
 * tables and links remain real selectable/searchable text in the saved PDF.
 */
export const exportReportPdf = async (options: PdfExportOptions): Promise<void> => {
  const frame = document.createElement('iframe');
  frame.setAttribute('aria-hidden', 'true');
  frame.title = normalizedFilename(options.filename, '.pdf');
  frame.style.cssText = 'position:fixed;right:0;bottom:0;width:1px;height:1px;border:0;opacity:0;pointer-events:none';
  const metadata = options.metadata.map(item => (
    `<div class="meta-item"><strong>${escape(item.label)}：</strong>${escape(item.value)}</div>`
  )).join('');
  frame.srcdoc = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>${escape(frame.title)}</title>
<style>
  @page { size:A4; margin:16mm 15mm 18mm; }
  * { box-sizing:border-box; }
  html,body { background:#fff; color:#172033; }
  body { margin:0; font-family:"PingFang SC","Microsoft YaHei","Noto Sans CJK SC",Arial,sans-serif; font-size:10.5pt; line-height:1.68; }
  header { border-bottom:2.5pt solid #0891b2; padding-bottom:12pt; margin-bottom:18pt; }
  .brand { color:#0e7490; font-size:8pt; letter-spacing:1.4pt; }
  h1 { color:#0f3f5c; font-size:20pt; line-height:1.25; margin:5pt 0 10pt; }
  h2 { color:#0e7490; font-size:14pt; border-left:3pt solid #06b6d4; padding-left:7pt; margin:18pt 0 7pt; break-after:avoid; }
  h3 { color:#155e75; font-size:11.5pt; margin:13pt 0 5pt; break-after:avoid; }
  p { margin:5pt 0; orphans:3; widows:3; }
  .metadata { display:grid; grid-template-columns:1fr 1fr; gap:3pt 18pt; color:#475569; font-size:8.8pt; }
  .meta-item { border-bottom:.5pt solid #e2e8f0; padding:2.5pt 0; }
  table { width:100%; border-collapse:collapse; margin:8pt 0 12pt; font-size:8.5pt; break-inside:auto; }
  thead { display:table-header-group; } tr { break-inside:avoid; }
  th { background:#e6f7fb; color:#164e63; font-weight:700; }
  th,td { border:.6pt solid #cbd5e1; padding:4.5pt; text-align:left; vertical-align:top; overflow-wrap:anywhere; }
  ul,ol { padding-left:18pt; } li { margin:2.5pt 0; }
  code { font-family:"SFMono-Regular",Consolas,monospace; font-size:8.5pt; background:#f1f5f9; padding:1pt 2pt; border-radius:2pt; overflow-wrap:anywhere; }
  blockquote { border-left:2pt solid #94a3b8; margin:8pt 0; padding:2pt 10pt; color:#475569; }
  a { color:#0369a1; text-decoration:none; }
  footer { position:fixed; bottom:-11mm; left:0; right:0; text-align:center; color:#94a3b8; font-size:7.5pt; }
</style></head><body>
<header><div class="brand">AUTOSEC GUARD · SECURITY ASSESSMENT</div><h1>${escape(options.title)}</h1><div class="metadata">${metadata}</div></header>
<main>${options.reportHtml}${options.appendixHtml ? `<section>${options.appendixHtml}</section>` : ''}</main>
<footer>AutoSec Guard · ${escape(frame.title)}</footer>
</body></html>`;
  document.body.appendChild(frame);

  await new Promise<void>((resolve, reject) => {
    const cleanup = () => window.setTimeout(() => frame.remove(), 1000);
    frame.addEventListener('error', () => {
      frame.remove();
      reject(new Error('无法创建文本 PDF 打印文档。'));
    }, { once: true });
    frame.addEventListener('load', async () => {
      try {
        await frame.contentDocument?.fonts?.ready;
        frame.contentWindow?.addEventListener('afterprint', cleanup, { once: true });
        frame.contentWindow?.focus();
        frame.contentWindow?.print();
        window.setTimeout(() => {
          if (frame.isConnected) frame.remove();
        }, 60_000);
        resolve();
      } catch (error) {
        frame.remove();
        reject(error);
      }
    }, { once: true });
  });
};

export const exportReportMarkdown = (options: MarkdownExportOptions): void => {
  const frontMatter = options.metadata
    .map(item => `- **${item.label}：** ${item.value}`)
    .join('\n');
  const content = `# ${options.title}\n\n${frontMatter}\n\n---\n\n${options.reportMarkdown.trim()}\n`;
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = normalizedFilename(options.filename, '.md');
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};
