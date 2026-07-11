import { describe, expect, it } from 'vitest';
import { backendPocToCatalogPoc } from './pocCatalog';

describe('runtime PoC catalog contract', () => {
  it('maps edge metadata without inventing a cloud execution plane', () => {
    const poc = backendPocToCatalogPoc({
      filename: 'network/01_CWE_200_Test_Active_Validation.py',
      display_id: 'POC-001',
      severity: 'High',
      required_params: ['target_ip'],
      execution_requirements: { required_capabilities: [], requires_edge: false },
    });
    expect(poc.id).toBe('POC-001');
    expect(poc.requiredParams).toEqual(['ip']);
    expect(poc).not.toHaveProperty('supportedExecutionPlanes');
    expect(poc).not.toHaveProperty('recommendedExecutionPlane');
  });
});
