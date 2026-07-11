// @vitest-environment jsdom
import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { AgentScanErrorBoundary } from './AgentScanErrorBoundary';

const Broken = () => {
  throw new Error('render failed');
};

describe('AgentScanErrorBoundary', () => {
  it('resets when the scan instance key changes', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const view = render(
      <AgentScanErrorBoundary resetKey="run-1"><Broken /></AgentScanErrorBoundary>,
    );
    expect(screen.getByText('Agent Scan 界面加载失败')).toBeTruthy();

    view.rerender(
      <AgentScanErrorBoundary resetKey="run-2"><div>fresh scanner</div></AgentScanErrorBoundary>,
    );
    expect(screen.getByText('fresh scanner')).toBeTruthy();
  });
});
