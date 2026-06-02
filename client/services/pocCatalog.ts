import { Category, POC, ParamType, ScanResult, Severity } from '../types';
import { listPocs } from './api';

const CATEGORY_BY_DIR: Record<string, Category> = {
  reconnaissance: Category.RECON,
  network: Category.NETWORK,
  canbus: Category.CANBUS,
  wireless: Category.WIRELESS,
  application: Category.APPLICATION,
  advanced: Category.ADVANCED,
};

const PARAM_ALIASES: Record<string, ParamType> = {
  target_ip: 'ip',
  ip: 'ip',
  host: 'ip',
  target_host: 'ip',
  target_port: 'port',
  port: 'port',
  bd_addr: 'bluetooth_mac',
  bluetooth_mac: 'bluetooth_mac',
  target_mac: 'target_mac',
  mac: 'target_mac',
  can_interface: 'can_interface',
  interface: 'interface',
  wifi_interface: 'interface',
  frequency: 'frequency',
  rf_frequency: 'frequency',
  url: 'url',
  usb_mount_point: 'usb_mount_point',
  expected_usb_serial: 'usb_adb_serial',
  usb_device_serial: 'usb_adb_serial',
  usb_adb_serial: 'usb_adb_serial',
  attacker_ip: 'attacker_ip',
};

const normalizePath = (value?: string | null): string => (
  String(value || '').replace(/\\/g, '/').replace(/^\.?\//, '').toLowerCase()
);

const basename = (value?: string | null): string => {
  const normalized = normalizePath(value);
  return normalized.split('/').pop() || '';
};

const stripPocPrefix = (value?: string | null): string => (
  basename(value).replace(/^\d+[a-z]?_/i, '').toLowerCase()
);

const normalizeSeverity = (value?: string | null): Severity => {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'critical') return Severity.CRITICAL;
  if (normalized === 'high') return Severity.HIGH;
  if (normalized === 'medium') return Severity.MEDIUM;
  if (normalized === 'low') return Severity.LOW;
  return Severity.INFO;
};

const categoryFromBackend = (item: any): Category => {
  const dir = String(item.category_dir || item.category || item.filename?.split('/')?.[0] || '').toLowerCase();
  return CATEGORY_BY_DIR[dir] || Category.ADVANCED;
};

const mapRequiredParams = (value: unknown): ParamType[] => {
  if (!Array.isArray(value)) return [];
  const params = value
    .map((item) => PARAM_ALIASES[String(item || '').trim()])
    .filter(Boolean);
  return Array.from(new Set(params));
};

const titleFromFilename = (filename?: string | null): string => {
  const name = basename(filename)
    .replace(/\.py$/i, '')
    .replace(/^\d+[a-z]?_/i, '')
    .replace(/_/g, ' ')
    .trim();
  return name || 'Unnamed PoC';
};

export const backendPocToCatalogPoc = (item: any): POC => {
  const filename = item.filename || '';
  const displayId = item.display_id || item.meta_display_id || basename(filename).replace(/\.py$/i, '');
  const name = item.poc_name || item.meta_poc_name || titleFromFilename(filename);
  const category = categoryFromBackend(item);
  const severity = normalizeSeverity(item.severity || item.meta_severity);
  const protocol = item.protocol || item.meta_protocol || category;
  const requiredParams = mapRequiredParams(item.required_params || item.meta_required_params);
  const destructiveLevel = String(item.meta_destructive_level || item.destructive_level || '').toLowerCase();
  const manualConfirmationRequired = Boolean(
    item.manual_confirmation_required ||
    item.is_disruptive ||
    item.execution_requirements?.requires_explicit_approval ||
    item.execution_requirements?.approval_required ||
    ['restart', 'dataloss', 'brick'].includes(destructiveLevel)
  );

  return {
    id: displayId,
    name,
    category,
    severity,
    cveId: item.cve_id || item.meta_cve_id || undefined,
    description: `${name} (${protocol})`,
    impact: manualConfirmationRequired
      ? 'This PoC may require operator confirmation before execution.'
      : 'This PoC verifies whether the target exposes the described attack surface.',
    remediation: 'Review the generated evidence and harden the affected service, interface, credential policy, or runtime exposure.',
    codeSnippet: item.content || '# PoC source is loaded from the backend registry.',
    requiredParams,
    pocFile: filename,
    supportedExecutionPlanes: item.supported_execution_planes || ['cloud', 'edge'],
    recommendedExecutionPlane: item.recommended_execution_plane || 'cloud',
    executionRequirements: item.execution_requirements,
    manualConfirmationRequired,
    targetOS: Array.isArray(item.meta_target_os || item.target_os)
      ? (item.meta_target_os || item.target_os)
      : undefined,
  };
};

export const fetchPocCatalog = async (): Promise<{ pocs: POC[]; total: number; error?: string }> => {
  const data = await listPocs();
  return {
    pocs: (data.pocs || []).map(backendPocToCatalogPoc),
    total: data.total || data.pocs?.length || 0,
    error: data.error,
  };
};

export const findPocInCatalog = (catalog: POC[], result: Pick<ScanResult, 'pocId' | 'name'> & { pocFile?: string }): POC | undefined => {
  const resId = String(result.pocId || '').toLowerCase();
  const resName = String(result.name || '').toLowerCase();
  const resFile = normalizePath((result as any).pocFile || result.pocId || result.name);
  const resBase = basename(resFile);
  const resClean = stripPocPrefix(resFile);

  return catalog.find((poc) => (
    poc.id.toLowerCase() === resId ||
    poc.name.toLowerCase() === resName ||
    normalizePath(poc.pocFile) === resFile ||
    basename(poc.pocFile) === resBase ||
    stripPocPrefix(poc.pocFile) === resClean
  ));
};
