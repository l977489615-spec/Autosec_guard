export enum Severity {
  CRITICAL = 'Critical',
  HIGH = 'High',
  MEDIUM = 'Medium',
  LOW = 'Low',
  INFO = 'Info'
}

export enum Category {
  RECON = 'Reconnaissance',
  NETWORK = 'Network/Service',
  CANBUS = 'CAN Bus/UDS',
  WIRELESS = 'Wireless/RF',
  APPLICATION = 'App/System',
  ADVANCED = 'Advanced/OTA'
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
  supportedExecutionPlanes?: ('cloud' | 'edge')[];
  recommendedExecutionPlane?: 'cloud' | 'edge';
  executionRequirements?: {
    required_capabilities: string[];
    requires_edge: boolean;
    cloud_only: boolean;
  };
  manualConfirmationRequired?: boolean;
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
  name?: string;
  severity?: string;
  description?: string;
}

export interface AttackGraphNode {
  id: string;
  type: 'entry' | 'vulnerability' | 'capability' | 'impact';
  label: string;
  severity: string;
  domain: string;
  evidence?: string;
}

export interface AttackGraphEdge {
  source: string;
  target: string;
  relation: string;
}

export interface AttackPath {
  id: string;
  title: string;
  riskScore: number;
  physicalImpact: string;
  nodes: string[];
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  paths: AttackPath[];
  summary?: string;
}

export interface PhysicalImpactAssessment {
  operationalContext: string;
  safetyLevel: string;
  impactDomains: string[];
  likelyEffects: string[];
  justification: string;
}

export interface RemediationAction {
  id: string;
  title: string;
  description: string;
  cost: 'low' | 'medium' | 'high';
  estimatedRiskReduction: number;
  affectsNodes: string[];
}

export interface RemediationPlan {
  beforeScore: number;
  afterScore: number;
  blockedPaths: string[];
  actions: RemediationAction[];
}

export interface StructuredAssessmentReport {
  summary: {
    targetName: string;
    riskScore: number;
    attackPathCount: number;
    physicalImpact: string;
  };
  findings: Array<{
    name: string;
    severity: string;
    evidence: string;
    domain: string;
  }>;
  attackPaths: AttackPath[];
  physicalImpact: PhysicalImpactAssessment;
  remediationPlan: RemediationPlan;
}

export interface AssessmentArtifacts {
  attackGraph?: AttackGraph;
  physicalImpact?: PhysicalImpactAssessment;
  remediationPlan?: RemediationPlan;
  structuredReport?: StructuredAssessmentReport;
}

export interface PhaseRecord {
  phase: string;
  status: string;
  attempt?: number;
  timestamp?: string;
  raw_output?: string;
  structured_output?: Record<string, any>;
  error?: string;
  history?: Array<{
    status: string;
    attempt?: number;
    timestamp?: string;
    error?: string;
  }>;
}

export interface PlannerStep {
  step: number;
  title: string;
  objective: string;
  success_criteria: string;
  depends_on?: number[];
}

export interface SupervisorEvent {
  scope: string;
  severity: string;
  message: string;
  phase?: string;
  timestamp?: string;
}

export interface SupervisorMetrics {
  total_events: number;
  repeat_tool_calls: number;
  no_progress_events: number;
  cascading_error_events: number;
  planner_fallbacks: number;
  deduplicated_steps: number;
  pruned_steps: number;
  execution_errors: number;
  confirmed_findings: number;
  skipped_plan_steps: number;
}

export interface SupervisorAdjustment {
  type: string;
  message: string;
  affected_steps?: number[];
  affected_pocs?: string[];
  timestamp?: string;
}

export interface ExecutionArtifactRecord {
  id: number;
  user_id: number;
  username?: string;
  session_id: string;
  trace_id?: string;
  artifact_type: string;
  poc_filename?: string;
  poc_name?: string;
  target_ip?: string;
  target_mac?: string;
  payload: Record<string, any>;
  created_at?: string;
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
  id: string; // Frontend/Session ID
  dbId?: number; // Backend Database ID
  targetName: string;
  connection: ConnectionParams;
  isConnected: boolean;
  startTime: string;
  endTime?: string;
  status: 'idle' | 'connecting' | 'running' | 'completed' | 'failed';
  mode: 'batch' | 'manual' | 'agent';
  logs: ScanLog[];
  results: ScanResult[];
  riskScore: number;
  aiReport?: string | null;
  username?: string;
  assessment?: AssessmentArtifacts;
  findings?: ScanResult[];
  phase_records?: PhaseRecord[];
  structured?: Record<string, any>;
}

export interface EdgeCapabilityFlags {
  usb: boolean;
  can: boolean;
  wifi: boolean;
  bluetooth: boolean;
  sdr: boolean;
  lsusb: boolean;
  iw: boolean;
  ip: boolean;
  bluetoothctl: boolean;
  hackrf: boolean;
}

export interface EdgeAgentRecord {
  agent_id: string;
  display_name: string;
  site_name?: string;
  status: string;
  capabilities: Record<string, any>;
  capability_flags?: EdgeCapabilityFlags;
  metadata?: Record<string, any>;
  last_seen_at?: string;
  created_at?: string;
  updated_at?: string;
}

export interface EdgeTaskRecord {
  task_id: string;
  edge_agent_id?: string;
  requested_by_user_id?: number;
  session_id?: string;
  trace_id?: string;
  poc_filename: string;
  params: Record<string, any>;
  status: string;
  result?: Record<string, any> | null;
  created_at?: string;
  updated_at?: string;
  started_at?: string;
  completed_at?: string;
}

export interface EdgeRequirementSummary {
  required_capabilities: string[];
  requires_edge: boolean;
  cloud_only: boolean;
}

export interface EdgeRecommendationItem {
  agent: EdgeAgentRecord;
  matches: boolean;
  missing_capabilities: string[];
}

export interface EdgeEnrollmentTokenRecord {
  id: number;
  label: string;
  status: string;  // active, used, revoked
  created_by: string;
  used_by_agent_id?: string;
  expires_at?: string;
  created_at?: string;
  used_at?: string;
}
