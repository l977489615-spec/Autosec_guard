export enum Severity {
  CRITICAL = 'Critical',
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low',
  INFO = 'Info'
}

export enum Category {
  IVI = 'IVI System',
  PROTOCOL = 'Vehicle Protocol', // CAN, UDS, LIN
  ADAS = 'ADAS/Autonomous',
  HARDWARE = 'Hardware/Interface',
  WIRELESS = 'Wireless/RF', // Bluetooth, Wi-Fi, Keyfob
  CLOUD = 'T-Box/Cloud'
}

export type ParamType = 'ip' | 'port' | 'can_interface' | 'bluetooth_mac' | 'url' | 'frequency' | 'baud_rate' | 'target_mac' | 'interface' | 'usb_mount_point' | 'attacker_ip';

export interface POC {
  id: string;
  name: string;
  category: Category;
  severity: Severity;
  cvssScore?: number;
  cveId?: string;
  description: string;
  impact: string;
  remediation: string;
  codeSnippet: string; // The static display version
  requiredParams: ParamType[];
  pocFile?: string; // Reference to the actual Python file in Pocs/
  // Function to generate the actual executable script based on user input
  scriptGenerator?: (params: Record<string, string>) => string;
  targetOS?: ('qnx' | 'android' | 'linux' | 'all')[]; // Used for intelligent OS skipping
}

export interface ScanLog {
  timestamp: string;
  message: string;
  type: 'info' | 'success' | 'error' | 'warning' | 'terminal';
}

export interface ScanResult {
  pocId: string;
  vulnerable: boolean;
  details: string;
  detectedAt: string;
  elapsedSeconds?: number;
}

export interface ConnectionParams {
  ip: string;
  port: string;
  bluetoothMac: string;
  canInterface: string;
  url: string;
  frequency: string;
  interface: string;
}

export interface ScanSession {
  id: string;
  targetName: string;
  connection: ConnectionParams;
  isConnected: boolean;
  startTime: string;
  endTime?: string;
  status: 'idle' | 'connecting' | 'running' | 'completed' | 'failed';
  mode: 'batch' | 'manual';
  logs: ScanLog[];
  results: ScanResult[];
  riskScore: number;
  aiReport?: string | null;
}