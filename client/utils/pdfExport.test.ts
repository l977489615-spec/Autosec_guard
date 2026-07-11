// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { exportReportMarkdown, exportReportPdf } from './pdfExport';

describe('report exports', () => {
  afterEach(() => {
    document.querySelectorAll('iframe, a').forEach(node => node.remove());
    vi.restoreAllMocks();
  });

  it('uses the native text print pipeline instead of rasterizing the report', async () => {
    const pending = exportReportPdf({
      filename: 'security-report',
      title: '安全评估报告',
      metadata: [{ label: '目标', value: 'test-target' }],
      reportHtml: '<h2>漏洞详情</h2><p>这是可以选择和搜索的正文</p>',
    });
    const frame = document.querySelector('iframe') as HTMLIFrameElement;
    expect(frame).not.toBeNull();
    expect(frame.srcdoc).toContain('这是可以选择和搜索的正文');
    expect(frame.srcdoc).not.toContain('canvas');
    vi.spyOn(frame.contentWindow as Window, 'focus').mockImplementation(() => undefined);
    const print = vi.spyOn(frame.contentWindow as Window, 'print').mockImplementation(() => undefined);
    frame.dispatchEvent(new Event('load'));
    await pending;
    expect(print).toHaveBeenCalledOnce();
  });

  it('downloads the complete report as markdown', () => {
    const createObjectURL = vi.fn(() => 'blob:report');
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: revokeObjectURL });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

    exportReportMarkdown({
      filename: 'security-report',
      title: '安全评估报告',
      metadata: [{ label: '目标', value: 'test-target' }],
      reportMarkdown: '## 漏洞详情\n\n完整证据。',
    });

    expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(click).toHaveBeenCalledOnce();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:report');
  });
});
