import { useState, useMemo, FormEvent } from 'react';
import {
  Shield, CheckCircle, AlertTriangle, AlertOctagon, Info, Download, Trash,
  ChevronRight, Search, RefreshCw, Layers, Server, Bookmark, X, Check,
  Terminal, FileText, Settings, Plus
} from 'lucide-react';

// ==========================================
// DATA STRUCTURES
// ==========================================

interface Framework {
  id: string;
  name: string;
  score: number;
  passed: number;
  failed: number;
  status: 'Pass' | 'Warning' | 'Fail';
  description: string;
}

interface Requirement {
  id: string;
  title: string;
  frameworkId: string;
  status: 'Pass' | 'Fail';
  score: number;
  failedResources: number;
  lastScan: string;
  description: string;
}

interface Violation {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  ruleId: string;
  finding: string;
  cluster: string;
  namespace: string;
  resource: string;
  framework: string;
  firstSeen: string;
  lastSeen: string;
  status: 'Open' | 'In Review' | 'Resolved';
  ownerTeam: string;
  description: string;
  remediation: string;
  scanners: string[];
  rawRules: string[];
  evidenceDigest: string;
}

interface EvidencePack {
  id: string;
  scanDate: string;
  framework: string;
  profile: string;
  cluster: string;
  status: 'Complete' | 'Incomplete';
  evaluated: number;
  passed: number;
  failed: number;
  scannersUsed: string[];
  downloadFormats: { format: string; size: string }[];
}

interface ClusterData {
  id: string;
  version: string;
  nodes: number;
  namespaces: number;
  complianceScore: number;
  lastScan: string;
  criticalFindings: number;
}

interface NamespaceData {
  name: string;
  team: string;
  workloads: number;
  complianceScore: number;
  openFindings: number;
}

interface NodeData {
  name: string;
  role: string;
  os: string;
  complianceScore: number;
  failedRules: number;
}

interface ExceptionRule {
  id: string;
  ruleId: string;
  namespace: string;
  reason: string;
  expires: string;
  approvedBy: string;
}

interface IntegrationItem {
  id: string;
  name: string;
  category: string;
  status: 'Connected' | 'Disconnected';
  lastSync: string;
}

// ==========================================
// INITIAL REALISTIC DATA SET
// ==========================================

const INITIAL_FRAMEWORKS: Framework[] = [
  { id: 'GDPR', name: 'GDPR Article 32', score: 72, passed: 36, failed: 14, status: 'Fail', description: 'Technical security requirements appropriate to risks of customer data handling.' },
  { id: 'PCI-DSS', name: 'PCI DSS v4.0', score: 82, passed: 106, failed: 22, status: 'Warning', description: 'Credit cardholder primary storage and transmission protocols.' },
  { id: 'CIS', name: 'CIS OpenShift Benchmark v1.4', score: 91, passed: 204, failed: 19, status: 'Warning', description: 'Hardening profiles for OpenShift endpoints and clusters.' },
  { id: 'NIST-STIG', name: 'NIST SP 800-53 (STIG)', score: 95, passed: 380, failed: 20, status: 'Pass', description: 'Mil-spec container isolation, secure routing, and SCC locks.' }
];

const INITIAL_REQUIREMENTS: Requirement[] = [
  { id: 'Art 32.1.a', title: 'Encryption of Personal Data', frameworkId: 'GDPR', status: 'Fail', score: 72, failedResources: 14, lastScan: 'Today', description: 'Continuous cryptographic protection of data-in-transit in namespaces.' },
  { id: 'Art 32.1.b', title: 'System confidentiality & resilience', frameworkId: 'GDPR', status: 'Pass', score: 100, failedResources: 0, lastScan: 'Today', description: 'Isolate container clusters against network side channels.' },
  { id: 'Art 25', title: 'Data protection by default', frameworkId: 'GDPR', status: 'Pass', score: 100, failedResources: 0, lastScan: 'Today', description: 'Avoid binding workloads to global privileged group namespaces.' },
  { id: 'PCI-Req 3.4', title: 'Encrypt Stored Cardholder Details', frameworkId: 'PCI-DSS', status: 'Fail', score: 76, failedResources: 12, lastScan: 'Today', description: 'Store account identifiers inside stateful volumes backed by active LUKS.' },
  { id: 'PCI-Req 10.2', title: 'Tamper-proof Log Trailing Engine', frameworkId: 'PCI-DSS', status: 'Pass', score: 100, failedResources: 0, lastScan: 'Today', description: 'Stream events to secure outside audit logging collectors.' }
];

const INITIAL_VIOLATIONS: Violation[] = [
  {
    id: 'VIO-001',
    severity: 'Critical',
    ruleId: 'CIS-5.2.5',
    finding: 'Privileged Container Allowed',
    cluster: 'prod-eu-1',
    namespace: 'payments',
    resource: 'deployment/payment-api',
    framework: 'CIS',
    firstSeen: '12 May 2026',
    lastSeen: 'Today',
    status: 'Open',
    ownerTeam: 'Finance',
    description: 'Workload payload requests root system capabilities or maps physical CPU host groups without bound SCC safeguards explicitly declared.',
    remediation: 'Configure SecurityContext configurations. Set runAsNonRoot: true, allowPrivilegeEscalation: false, and drop all default Linux capabilities.',
    scanners: ['Kubescape Engine v3', 'OpenShift SCC Compliance Operator'],
    rawRules: ['KSV-012', 'xccdf_org.ssgproject.content_rule_openshift_scc_limit_privilege'],
    evidenceDigest: 'Root UID evaluation returned 0 on container startup for payment-api service workload.'
  },
  {
    id: 'VIO-002',
    severity: 'Critical',
    ruleId: 'PCI-DSS-3.4.1',
    finding: 'Raw Account Data Stored Plaintext',
    cluster: 'prod-eu-1',
    namespace: 'payments',
    resource: 'statefulset/cc-db',
    framework: 'PCI DSS',
    firstSeen: '14 May 2026',
    lastSeen: 'Today',
    status: 'In Review',
    ownerTeam: 'Finance',
    description: 'Cryptographic policy auditor located plain text credit card parameters residing on non-LUKS encrypted ephemeral PV storage systems.',
    remediation: 'Attach custom OpenShift CSI driver that enforces transparent persistent volume encryption at the storage layer block level.',
    scanners: ['Checkov Compliance Scanner', 'Falco Sys Audit Agent'],
    rawRules: ['CKV_K8S_31', 'FALCO_FILE_WRITE-011'],
    evidenceDigest: 'Plaintext card format matched on device mounting path /var/lib/cc-db.'
  },
  {
    id: 'VIO-003',
    severity: 'High',
    ruleId: 'KSV-041',
    finding: 'HostPID Namespace Share Enabled',
    cluster: 'prod-us-1',
    namespace: 'billing',
    resource: 'deployment/billing-sync',
    framework: 'CIS',
    firstSeen: '18 May 2026',
    lastSeen: 'Today',
    status: 'Open',
    ownerTeam: 'Billing',
    description: 'Workload template specifies hostPID: true, bypassing target security context and exposing host processes directly to pod spaces.',
    remediation: 'Reconfigure template payload. Omit hostPID properties or set hostPID explicitly to false.',
    scanners: ['OPA Gatekeeper Engine', 'Kubescape Daemon v3'],
    rawRules: ['KSV-041', 'OPA-NET-ACCESS-08'],
    evidenceDigest: 'spec.hostPID: true evaluated on cluster workload metadata check.'
  }
];

const INITIAL_EVIDENCE_PACKS: EvidencePack[] = [
  {
    id: 'EVI-001',
    scanDate: '19-May-2026',
    framework: 'PCI DSS v4.0',
    profile: 'ocp4-pci-dss',
    cluster: 'prod-eu-1',
    status: 'Complete',
    evaluated: 128,
    passed: 106,
    failed: 22,
    scannersUsed: ['OpenSCAP Compliance Daemon', 'Kubescape Engine v3', 'OPA Gatekeeper'],
    downloadFormats: [
      { format: 'PDF Audit Report', size: '1.4 MB' },
      { format: 'OSCAL JSON Evidential Record', size: '840 KB' },
      { format: 'ARF XML Report File', size: '3.1 MB' }
    ]
  },
  {
    id: 'EVI-002',
    scanDate: '19-May-2026',
    framework: 'CIS OpenShift Benchmark',
    profile: 'ocp4-cis',
    cluster: 'prod-us-1',
    status: 'Complete',
    evaluated: 223,
    passed: 204,
    failed: 19,
    scannersUsed: ['OpenSCAP Compliance Daemon', 'Kubescape Engine', 'Kube API Compliance Agent'],
    downloadFormats: [
      { format: 'PDF Audit Report', size: '2.1 MB' },
      { format: 'OSCAL JSON Evidential Record', size: '1.2 MB' }
    ]
  }
];

const CLUSTERS_DATA: ClusterData[] = [
  { id: 'prod-eu-1', version: 'OCP 4.15', nodes: 24, namespaces: 86, complianceScore: 78, lastScan: '1h ago', criticalFindings: 12 },
  { id: 'prod-us-1', version: 'OCP 4.15', nodes: 18, namespaces: 64, complianceScore: 89, lastScan: '2h ago', criticalFindings: 4 },
  { id: 'dev-us-2', version: 'OCP 4.14', nodes: 6, namespaces: 12, complianceScore: 96, lastScan: '4h ago', criticalFindings: 0 }
];

const NAMESPACES_DATA: Record<string, NamespaceData[]> = {
  'prod-eu-1': [
    { name: 'payments', team: 'Finance', workloads: 18, complianceScore: 71, openFindings: 12 },
    { name: 'billing', team: 'Finance', workloads: 11, complianceScore: 89, openFindings: 3 },
    { name: 'auth', team: 'Identity', workloads: 8, complianceScore: 100, openFindings: 0 },
    { name: 'monitoring', team: 'Platform', workloads: 22, complianceScore: 96, openFindings: 0 }
  ],
  'prod-us-1': [
    { name: 'billing', team: 'Finance', workloads: 14, complianceScore: 85, openFindings: 4 },
    { name: 'infrastructure', team: 'Platform', workloads: 19, complianceScore: 98, openFindings: 0 }
  ],
  'dev-us-2': [
    { name: 'default', team: 'Platform', workloads: 5, complianceScore: 96, openFindings: 0 }
  ]
};

const NODES_DATA: Record<string, NodeData[]> = {
  'prod-eu-1': [
    { name: 'worker-eu-1a', role: 'Worker', os: 'RHCOS (Enterprise CoreOS)', complianceScore: 82, failedRules: 14 },
    { name: 'worker-eu-1b', role: 'Worker', os: 'RHCOS (Enterprise CoreOS)', complianceScore: 91, failedRules: 6 },
    { name: 'master-eu-1a', role: 'Control Plane', os: 'RHCOS (Enterprise CoreOS)', complianceScore: 96, failedRules: 1 }
  ],
  'prod-us-1': [
    { name: 'worker-us-1c', role: 'Worker', os: 'RHCOS (Enterprise CoreOS)', complianceScore: 90, failedRules: 4 }
  ],
  'dev-us-2': [
    { name: 'worker-dev-2a', role: 'Worker', os: 'RHCOS (Enterprise CoreOS)', complianceScore: 100, failedRules: 0 }
  ]
};

const INITIAL_EXCEPTIONS: ExceptionRule[] = [
  { id: 'EXP-001', ruleId: 'CIS-5.2.5', namespace: 'payments', reason: 'Legacy payment-v1 backend workload running temporarily during bank API migration transition window', expires: '2026-06-30', approvedBy: 'Lead SRE Officer' },
  { id: 'EXP-002', ruleId: 'KSV-041', namespace: 'monitoring', reason: 'System telemetry agents require HostNetwork & HostPID access on master nodes', expires: '2026-12-15', approvedBy: 'CISO compliance director' }
];

const INITIAL_INTEGRATIONS: IntegrationItem[] = [
  { id: 'openshift-api', name: 'OpenShift Config Operator API Server', category: 'Platform Audits', status: 'Connected', lastSync: '12m ago' },
  { id: 'argocd', name: 'OpenShift GitOps (ArgoCD) Auditor Webhook', category: 'GitOps Pipeline', status: 'Connected', lastSync: '1h ago' },
  { id: 'slack', name: 'Slack Ops Alerts Webhook Channel', category: 'SRE Communication', status: 'Connected', lastSync: '3h ago' },
  { id: 'servicenow', name: 'ServiceNow ITSM Connector Service', category: 'Ticket Tracking', status: 'Disconnected', lastSync: '2d ago' }
];

export default function App() {
  // Navigation State
  const [currentPage, setCurrentPage] = useState<'overview' | 'compliance' | 'violations' | 'evidence' | 'clusters' | 'admin'>('overview');
  const [activeBreadcrumb, setActiveBreadcrumb] = useState<string[]>(['Compliance Dashboard']);

  // Dynamic state stores
  const [frameworks] = useState<Framework[]>(INITIAL_FRAMEWORKS);
  const [requirements] = useState<Requirement[]>(INITIAL_REQUIREMENTS);
  const [violations, setViolations] = useState<Violation[]>(INITIAL_VIOLATIONS);
  const [evidencePacks] = useState<EvidencePack[]>(INITIAL_EVIDENCE_PACKS);
  const [clusters] = useState<ClusterData[]>(CLUSTERS_DATA);
  const [exceptions, setExceptions] = useState<ExceptionRule[]>(INITIAL_EXCEPTIONS);
  const [integrations, setIntegrations] = useState<IntegrationItem[]>(INITIAL_INTEGRATIONS);

  // Search & Filter criteria states
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedFramework, setSelectedFramework] = useState('ALL');
  const [selectedCluster, setSelectedCluster] = useState('ALL');
  const [selectedNamespace, setSelectedNamespace] = useState('ALL');

  // Multi drill-down details
  const [activeFramework, setActiveFramework] = useState<Framework | null>(null);
  const [activeViolation, setActiveViolation] = useState<Violation | null>(null);
  const [activeEvidence, setActiveEvidence] = useState<EvidencePack | null>(null);
  const [activeCluster, setActiveCluster] = useState<ClusterData | null>(null);
  const [activeClusterTab, setActiveClusterTab] = useState<'namespaces' | 'nodes'>('namespaces');

  // Controls
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);
  const [adminActiveTab, setAdminActiveTab] = useState<'profiles' | 'exceptions' | 'integrations'>('exceptions');

  // Built form states
  const [newExpRule, setNewExpRule] = useState('');
  const [newExpNamespace, setNewExpNamespace] = useState('payments');
  const [newExpReason, setNewExpReason] = useState('');
  const [newExpExpiry, setNewExpExpiry] = useState('2026-06-30');
  const [formSuccessMsg, setFormSuccessMsg] = useState('');

  // Settle calculations
  const totalFindingsCount = violations.length;
  const criticalFindingsCount = violations.filter(v => v.severity === 'Critical').length;

  const handleResetFilters = () => {
    setSelectedSeverity('ALL');
    setSelectedFramework('ALL');
    setSelectedCluster('ALL');
    setSelectedNamespace('ALL');
    setSearchQuery('');
  };

  const handleCreateException = (e: FormEvent) => {
    e.preventDefault();
    if (!newExpRule || !newExpReason) {
      alert('Required parameters missing: Rule ID and Justification fields must be declared.');
      return;
    }
    const created: ExceptionRule = {
      id: `EXP-0${exceptions.length + 10}`,
      ruleId: newExpRule,
      namespace: newExpNamespace,
      reason: newExpReason,
      expires: newExpExpiry,
      approvedBy: 'Platform Admin SRE Security'
    };
    setExceptions([created, ...exceptions]);
    setNewExpRule('');
    setNewExpReason('');
    setFormSuccessMsg('Exception has been compiled successfully & hot-dispatched to the evaluation engine!');
    setTimeout(() => setFormSuccessMsg(''), 4000);
  };

  const handleDeleteException = (id: string) => {
    setExceptions(exceptions.filter(ex => ex.id !== id));
  };

  const syncIntegration = (id: string) => {
    setIntegrations(integrations.map(itm => (
      itm.id === id ? { ...itm, status: itm.status === 'Connected' ? 'Disconnected' : 'Connected', lastSync: 'Just now' } : itm
    )));
  };

  // Safe navigation paths for product owner hierarchical breadcrumbs
  const navigateByBreadcrumb = (index: number, nameText: string) => {
    if (index === 0) {
      setCurrentPage('overview');
      setActiveBreadcrumb(['Compliance Dashboard']);
      setActiveCluster(null);
      setActiveFramework(null);
    } else {
      if (nameText.startsWith('prod-') || nameText.startsWith('dev-')) {
        const found = clusters.find(cl => cl.id === nameText);
        if (found) {
          setActiveCluster(found);
          setCurrentPage('clusters');
          setActiveBreadcrumb(['Compliance Dashboard', found.id]);
        }
      } else if (['payments', 'billing', 'monitoring', 'auth'].includes(nameText)) {
        const parentId = activeBreadcrumb[1] || 'prod-eu-1';
        const found = clusters.find(cl => cl.id === parentId);
        if (found) {
          setActiveCluster(found);
          setActiveClusterTab('namespaces');
          setCurrentPage('clusters');
          setActiveBreadcrumb(['Compliance Dashboard', found.id, nameText]);
        }
      } else {
        setCurrentPage('violations');
      }
    }
  };

  const triggerViolationRemediation = (v: Violation) => {
    setActiveViolation(v);
    setShowTechnicalDetails(false);
    setActiveBreadcrumb(['Compliance Dashboard', 'Violations', v.cluster, v.namespace, v.ruleId]);
  };

  const filteredViolationsList = useMemo(() => {
    return violations.filter(v => {
      const matchesSearch = searchQuery === '' || 
        v.finding.toLowerCase().includes(searchQuery.toLowerCase()) ||
        v.resource.toLowerCase().includes(searchQuery.toLowerCase()) ||
        v.ruleId.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesSeverity = selectedSeverity === 'ALL' || v.severity === selectedSeverity;
      const matchesFramework = selectedFramework === 'ALL' || v.framework === selectedFramework;
      const matchesCluster = selectedCluster === 'ALL' || v.cluster === selectedCluster;
      const matchesNamespace = selectedNamespace === 'ALL' || v.namespace === selectedNamespace;

      return matchesSearch && matchesSeverity && matchesFramework && matchesCluster && matchesNamespace;
    });
  }, [violations, searchQuery, selectedSeverity, selectedFramework, selectedCluster, selectedNamespace]);

  return (
    <div className="min-h-screen bg-[#faf9f6] text-[#1c1c1a] font-sans antialiased flex flex-col md:flex-row">
      
      {/* SIDEBAR NAVIGATION CONTROL */}
      <aside className="w-full md:w-64 bg-[#f1f0ea] border-r border-[#d8d7cf] flex flex-col shrink-0">
        
        <div className="p-6 border-b border-[#d8d7cf] flex items-center gap-2.5">
          <div className="h-9 w-9 bg-[#1c1c1a] text-white flex items-center justify-center rounded-lg">
            <Shield className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-tight">OpenShift Platform</h1>
            <p className="text-[10px] text-[#70706a] uppercase font-bold tracking-wider">Compliance Audit</p>
          </div>
        </div>

        <nav className="p-4 space-y-1.5 flex-1 animate-fadeIn">
          <button
            onClick={() => { setCurrentPage('overview'); handleResetFilters(); setActiveBreadcrumb(['Compliance Dashboard']); }}
            className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${currentPage === 'overview' ? 'bg-[#1c1c1a] text-white' : 'text-[#50504a] hover:bg-[#e4e3dc] hover:text-[#1c1c1a]'}`}
          >
            <Layers className="h-4 w-4" />
            Overview Dashboard
          </button>

          <button
            onClick={() => { setCurrentPage('compliance'); handleResetFilters(); setActiveFramework(null); setActiveBreadcrumb(['Compliance Dashboard', 'Standards']); }}
            className={`w-full flex items-center justify-between px-3 py-2 text-xs font-semibold rounded-lg transition-all ${currentPage === 'compliance' ? 'bg-[#1c1c1a] text-white' : 'text-[#50504a] hover:bg-[#e4e3dc] hover:text-[#1c1c1a]'}`}
          >
            <span className="flex items-center gap-3">
              <Shield className="h-4 w-4" />
              Compliance Mappings
            </span>
            <span className="bg-[#dfded6] text-[#3c3c36] text-[9px] px-1.5 py-0.2 rounded font-mono font-bold">4</span>
          </button>

          <button
            onClick={() => { setCurrentPage('violations'); handleResetFilters(); setActiveViolation(null); setActiveBreadcrumb(['Compliance Dashboard', 'Violations']); }}
            className={`w-full flex items-center justify-between px-3 py-2 text-xs font-semibold rounded-lg transition-all ${currentPage === 'violations' ? 'bg-[#1c1c1a] text-white' : 'text-[#50504a] hover:bg-[#e4e3dc] hover:text-[#1c1c1a]'}`}
          >
            <span className="flex items-center gap-3">
              <AlertTriangle className="h-4 w-4" />
              Resource Gaps
            </span>
            <span className="bg-red-200 text-red-900 text-[10px] px-1.5 py-0.2 rounded font-bold font-mono">
              {violations.length}
            </span>
          </button>

          <button
            onClick={() => { setCurrentPage('evidence'); handleResetFilters(); setActiveEvidence(null); setActiveBreadcrumb(['Compliance Dashboard', 'Evidence Packs']); }}
            className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${currentPage === 'evidence' ? 'bg-[#1c1c1a] text-white' : 'text-[#50504a] hover:bg-[#e4e3dc] hover:text-[#1c1c1a]'}`}
          >
            <FileText className="h-4 w-4" />
            Auditor Evidence Records
          </button>

          <button
            onClick={() => { setCurrentPage('clusters'); handleResetFilters(); setActiveCluster(null); setActiveBreadcrumb(['Compliance Dashboard', 'Topology']); }}
            className={`w-full flex items-center justify-between px-3 py-2 text-xs font-semibold rounded-lg transition-all ${currentPage === 'clusters' ? 'bg-[#1c1c1a] text-white' : 'text-[#50504a] hover:bg-[#e4e3dc] hover:text-[#1c1c1a]'}`}
          >
            <span className="flex items-center gap-3">
              <Server className="h-4 w-4" />
              Cluster Namespaces Nodes
            </span>
          </button>

          <button
            onClick={() => { setCurrentPage('admin'); handleResetFilters(); setActiveBreadcrumb(['Compliance Dashboard', 'Administration']); }}
            className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-semibold rounded-lg transition-all ${currentPage === 'admin' ? 'bg-[#1c1c1a] text-white' : 'text-[#50504a] hover:bg-[#e4e3dc] hover:text-[#1c1c1a]'}`}
          >
            <Settings className="h-4 w-4" />
            Control Center & Rules
          </button>
        </nav>

        {/* User context footer credentials */}
        <div className="p-4 border-t border-[#d8d7cf] bg-[#e8e7df] mt-auto">
          <div className="flex items-center gap-1.5 mb-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-ping"></span>
            <span className="text-[9px] font-mono font-bold text-[#5c5c56]">CONTINUOUS AUTOMATION</span>
          </div>
          <p className="text-xs font-bold text-[#1c1c1a] truncate">asifanu1998@gmail.com</p>
          <p className="text-[10px] text-[#70706a]">OpenShift SRE Compliance</p>
        </div>
      </aside>

      {/* MAIN LAYOUT CANVAS */}
      <main className="flex-1 flex flex-col min-w-0">
        
        {/* HEADER BREADCRUMBS RAIL */}
        <header className="h-16 border-b border-[#dfded6] bg-[#fcfbfa] px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-1.5 text-xs text-[#70706a] font-medium">
            {activeBreadcrumb.map((item, idx) => (
              <div key={idx} className="flex items-center gap-1 text-[11px]">
                {idx > 0 && <ChevronRight className="h-3 w-3 text-[#b0af9f]" />}
                <button
                  onClick={() => navigateByBreadcrumb(idx, item)}
                  className={`hover:text-[#1c1c1a] transition-all font-bold ${idx === activeBreadcrumb.length - 1 ? 'text-[#1c1c1a]' : 'text-[#70706a] hover:underline'}`}
                >
                  {item}
                </button>
              </div>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <span className="text-[10px] font-mono text-[#5a5a54] bg-[#f1f0e8] px-2 py-0.5 rounded border border-[#dfded6]">
              2026-05-21 Live
            </span>
          </div>
        </header>

        {/* WORKSPACE CONTENT AREA WITH CONDITIONAL ROUTING */}
        <div className="p-6 md:p-8 flex-1 overflow-auto space-y-6">

          {/* ==================== 1. SCENE: OVERVIEW ==================== */}
          {currentPage === 'overview' && (
            <div className="space-y-6 animate-fadeIn">
              
              {/* Product overview explain */}
              <div className="bg-[#1c1c1a] text-white p-6 rounded-xl shadow-xs relative overflow-hidden">
                <div className="max-w-3xl relative z-10 space-y-2">
                  <span className="bg-amber-400 text-black text-[9px] font-extrabold px-2 py-0.5 rounded tracking-widest uppercase">
                    Regulatory Compliance Framework Unified Mappings
                  </span>
                  <h2 className="text-xl font-bold font-sans">OpenShift security compliance hub</h2>
                  <p className="text-xs text-[#bfbeb7] leading-relaxed">
                    This system filters scanner noise from Falco and OPA into human-led Article matrices. Platform teams track failed SCC limits or raw network parameters isolated mapped strictly into resource structures.
                  </p>
                </div>
              </div>

              {/* HIGH LEVEL STATS */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white p-5 rounded-lg border border-[#e2e2d9] shadow-xs">
                  <p className="text-[10px] font-bold text-[#70706a] uppercase">Average Compliance Weight</p>
                  <p className="text-3xl font-extrabold mt-1 text-[#1c1c1a]">86.2%</p>
                  <p className="text-[10px] text-emerald-700 font-bold mt-2">✓ Within critical baseline threshold</p>
                </div>

                <div className="bg-white p-5 rounded-lg border border-[#e2e2d9] shadow-xs">
                  <p className="text-[10px] font-bold text-[#70706a] uppercase">Active Resource Gaps</p>
                  <p className="text-3xl font-extrabold mt-1 text-red-700">{totalFindingsCount}</p>
                  <p className="text-[10px] text-red-700 font-bold mt-2">⚠ Requires SRE patch context</p>
                </div>

                <div className="bg-white p-5 rounded-lg border border-[#e2e2d9] shadow-xs">
                  <p className="text-[10px] font-bold text-[#70706a] uppercase">GDPR Failing Controls</p>
                  <p className="text-3xl font-extrabold mt-1 text-[#1c1c1a]">14</p>
                  <p className="text-[10px] text-[#70706a] mt-2">Under evaluation namespace target</p>
                </div>

                <div className="bg-white p-5 rounded-lg border border-[#e2e2d9] shadow-xs">
                  <p className="text-[10px] font-bold text-[#70706a] uppercase">Pending Policy Exceptions</p>
                  <p className="text-3xl font-extrabold mt-1 text-[#1c1c1a]">{exceptions.length}</p>
                  <p className="text-[10px] text-amber-700 font-bold mt-2">Expires June 30th context</p>
                </div>
              </div>

              {/* FRAMEWORK PROGRESS AND TOPOLOGY MATRIX */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Regulatory frameworks */}
                <div className="bg-white p-6 rounded-lg border border-[#e2e2d9] lg:col-span-7 space-y-4 shadow-xs">
                  <h3 className="text-sm font-bold text-[#1c1c1a]">Fulfilling Framework Status Summaries</h3>
                  <div className="space-y-3">
                    {frameworks.map((f) => (
                      <div key={f.id} className="p-3.5 rounded bg-[#faf9f6] border border-[#e2e2d9] space-y-2">
                        <div className="flex justify-between items-center text-xs">
                          <span className="font-bold text-[#1c1c1a]">{f.name} ({f.id})</span>
                          <span className={`text-[9px] font-extrabold px-1.5 py-0.2 rounded uppercase ${
                            f.status === 'Pass' ? 'bg-emerald-50 text-emerald-800' :
                            f.status === 'Warning' ? 'bg-amber-50 text-amber-800' : 'bg-red-50 text-red-800'
                          }`}>
                            {f.status}
                          </span>
                        </div>
                        <div className="w-full bg-[#dfded6] rounded-full h-1">
                          <div 
                            className={`h-1 rounded-full ${f.score > 90 ? 'bg-emerald-600' : f.score > 80 ? 'bg-amber-500' : 'bg-red-600'}`}
                            style={{ width: `${f.score}%` }}
                          />
                        </div>
                        <div className="flex justify-between text-[11px] text-[#70706a]">
                          <span>{f.passed} evaluation checkpoints passing ok</span>
                          <span className="font-bold text-red-800">{f.failed} failures</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* SRE physical clusters quickview */}
                <div className="bg-white p-6 rounded-lg border border-[#e2e2d9] lg:col-span-5 space-y-4 shadow-xs">
                  <div className="flex justify-between items-center">
                    <h3 className="text-sm font-bold text-[#1c1c1a]">Physical Monitored Clusters</h3>
                    <button onClick={() => setCurrentPage('clusters')} className="text-xs text-amber-805 font-bold hover:underline">All Clusters</button>
                  </div>
                  <div className="space-y-3.5">
                    {clusters.map((cl) => (
                      <div 
                        key={cl.id} 
                        onClick={() => { setActiveCluster(cl); setCurrentPage('clusters'); }}
                        className="p-3 rounded border border-[#dfded6] hover:bg-[#faf9f6]/80 transition-all cursor-pointer flex justify-between items-center"
                      >
                        <div>
                          <p className="text-xs font-bold font-mono text-[#1c1c1a]">{cl.id}</p>
                          <span className="text-[10px] text-[#70706a]">{cl.nodes} physical nodes | {cl.namespaces} namespaces defined</span>
                        </div>
                        <div className="text-right">
                          <span className="text-xs font-bold block">{cl.complianceScore}% Score</span>
                          <span className="text-[9px] font-mono text-red-700 font-bold">{cl.criticalFindings} open criticals</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

              </div>

              {/* QUICK RECTIFY INTERACTIVE MATRIX */}
              <div className="bg-white p-6 rounded-lg border border-[#e2e2d9] shadow-xs space-y-3">
                <h3 className="text-sm font-bold text-[#1c1c1a]">Immediate Attention Actionable Gaps</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-800 border-collapse animate-fadeIn">
                    <thead>
                      <tr className="border-b border-[#e2e2d9] pb-2 text-[#70706a] font-bold uppercase bg-[#faf9f6]">
                        <th className="p-2">Severity</th>
                        <th className="p-2">Namespace Target</th>
                        <th className="p-2">Resource Spec</th>
                        <th className="p-2">Technical Finding Name</th>
                        <th className="p-2">Framework Standards</th>
                        <th className="p-2 text-right">Auditor Assessment</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#f5f5f0]">
                      {violations.map((v) => (
                        <tr key={v.id} className="hover:bg-[#faf9f6]/90 transition-colors">
                          <td className="p-2 text-[10px]">
                            <span className="bg-red-50 text-red-800 px-2 py-0.5 rounded font-bold border border-red-200">
                              {v.severity}
                            </span>
                          </td>
                          <td className="p-2 font-mono font-bold text-[#1e40af]">{v.namespace}</td>
                          <td className="p-2 font-mono text-gray-500">{v.resource}</td>
                          <td className="p-2 font-semibold text-zinc-900">{v.finding}</td>
                          <td className="p-2 font-mono text-[10px]">{v.framework}</td>
                          <td className="p-2 text-right">
                            <button 
                              onClick={() => triggerViolationRemediation(v)}
                              className="bg-[#faf9f6] text-black border border-[#d8d7cf] hover:text-white hover:bg-black p-1 px-2.5 rounded font-extrabold transition-all"
                            >
                              Remedy Gaps →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* ==================== 2. SCENE: COMPLIANCE MATRIX ==================== */}
          {currentPage === 'compliance' && (
            <div className="space-y-6">
              
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-[#1c1c1a]">Regulatory Framework Status Table</h2>
                  <p className="text-xs text-[#70706a]">Unified translation of raw scanner artifacts into legislative requirements.</p>
                </div>

                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[#70706a]" />
                    <input 
                      type="text" 
                      placeholder="Filter articles..." 
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="pl-8 pr-3 py-1.5 bg-white border border-[#dfded6] rounded text-xs focus:ring-1 focus:ring-black focus:outline-none"
                    />
                  </div>
                  <button 
                    onClick={() => {
                      alert("Compiling custom PDF ledger matching secure SHA-256 token matrices...");
                    }}
                    className="p-1.5 px-3.5 text-xs bg-[#1c1c1a] text-white rounded font-bold hover:bg-zinc-950 flex items-center gap-1.5"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download PDF
                  </button>
                </div>
              </div>

              {/* Segment selectors */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {frameworks.map((f) => (
                  <div 
                    key={f.id}
                    onClick={() => setActiveFramework(f)}
                    className={`p-4 rounded-lg cursor-pointer transition-all border ${
                      activeFramework?.id === f.id ? 'bg-white border-[#1c1c1a] ring-2 ring-[#1c1c1a]' : 'bg-white border-[#dfded6] hover:border-[#1c1c1a]'
                    }`}
                  >
                    <div className="flex justify-between items-start text-[10px]">
                      <span className="font-mono bg-[#dfded6] px-1.5 rounded font-bold uppercase">{f.id}</span>
                      <span className={`px-1 py-0.2 rounded font-bold uppercase ${f.status === 'Pass' ? 'text-emerald-800' : 'text-red-700'}`}>{f.status}</span>
                    </div>
                    <h4 className="text-xs font-bold text-[#1c1c1a] mt-2.5 h-8 line-clamp-2">{f.name}</h4>
                    <div className="mt-3.5 pt-2.5 border-t border-[#f5f5f0] flex items-end justify-between">
                      <span className="text-xl font-mono font-bold">{f.score}%</span>
                      <span className="text-[10px] font-bold text-amber-850">Select standard →</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Requirements details matrix */}
              <div className="bg-white rounded-lg border border-[#e2e2d9] p-6 space-y-4 shadow-xs">
                <div className="flex items-center justify-between border-b border-[#f5f5f0] pb-3">
                  <h3 className="text-xs uppercase font-extrabold text-[#70706a]">
                    {activeFramework ? `${activeFramework.name} requirements matrix details` : 'Unified mapped requirement metrics'}
                  </h3>
                  {activeFramework && (
                    <button onClick={() => setActiveFramework(null)} className="text-xs text-red-700 font-bold">Show All</button>
                  )}
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#dfded6] pb-2 text-[#70706a] font-bold uppercase bg-[#faf9f6]">
                        <th className="p-2">Reg ID</th>
                        <th className="p-2">Requirement Specification Title</th>
                        <th className="p-2">Control Status</th>
                        <th className="p-2">Compliance Score</th>
                        <th className="p-2">Failing Workloads</th>
                        <th className="p-2 text-right">Audit Schedule</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#f5f5f0]">
                      {requirements
                        .filter(r => !activeFramework || r.frameworkId === activeFramework.id)
                        .filter(r => r.title.toLowerCase().includes(searchQuery.toLowerCase()) || r.id.toLowerCase().includes(searchQuery.toLowerCase()))
                        .map((req) => (
                          <tr key={req.id} className="hover:bg-[#faf9f6]/90 transition-colors">
                            <td className="p-3 font-mono font-bold text-zinc-900">{req.id}</td>
                            <td className="p-3">
                              <p className="font-bold text-[#1c1c1a]">{req.title}</p>
                              <p className="text-[11px] text-[#70706a]">{req.description}</p>
                            </td>
                            <td className="p-3">
                              <span className={`px-2 py-0.5 rounded font-bold ${req.status === 'Pass' ? 'bg-emerald-50 text-emerald-800' : 'bg-red-50 text-red-800'}`}>
                                {req.status === 'Pass' ? 'PASSED' : 'FAILED'}
                              </span>
                            </td>
                            <td className="p-3 font-mono font-bold">{req.score}%</td>
                            <td className="p-3">
                              {req.failedResources > 0 ? (
                                <button 
                                  onClick={() => { setSelectedFramework(req.frameworkId === 'GDPR' ? 'GDPR' : 'PCI DSS'); setCurrentPage('violations'); }}
                                  className="text-xs text-red-700 bg-red-50 border border-red-200 p-0.5 px-2 rounded hover:bg-red-100 font-bold"
                                >
                                  {req.failedResources} failing physical pods
                                </button>
                              ) : (
                                <span className="text-emerald-800">0 failures</span>
                              )}
                            </td>
                            <td className="p-3 text-right text-gray-500 font-mono">{req.lastScan}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          )}

          {/* ==================== 3. SCENE: VIOLATIONS SRE HUB ==================== */}
          {currentPage === 'violations' && (
            <div className="space-y-6">

              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-[#1c1c1a]">Active Resource Real-world Violations</h2>
                  <p className="text-xs text-[#70706a]">Filter workloads directly. Map failing elements to security exception rules.</p>
                </div>
                
                <div className="flex items-center gap-2">
                  <button onClick={handleResetFilters} className="text-xs font-semibold p-1.5 px-3 border border-[#dfded6] rounded bg-white hover:bg-[#faf9f6]">Reset Filters</button>
                  <button onClick={() => alert("CSV Export complete. Download cached locally.")} className="p-1 px-2.5 text-xs bg-white text-[#1c1c1a] border border-[#d8d7cf] rounded font-bold hover:bg-[#faf9f6]">Export CSV</button>
                </div>
              </div>

              {/* SEARCH & FILTERS CONFIGS */}
              <div className="bg-[#f0ede6] p-4 rounded-lg border border-[#d8d7cf] grid grid-cols-1 md:grid-cols-5 gap-3.5">
                <div className="md:col-span-2 space-y-1">
                  <span className="text-[10px] font-bold text-[#55554f] uppercase tracking-wider block">Find by identifier</span>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[#70706a]" />
                    <input 
                      type="text" 
                      placeholder="Search container rule finding..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-8 pr-3 py-1 bg-white border border-[#c4c3bb] rounded text-xs focus:ring-1 focus:ring-black focus:outline-none"
                    />
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] font-bold text-[#55554f] uppercase tracking-wider block">Severity filter</span>
                  <select 
                    value={selectedSeverity}
                    onChange={(e) => setSelectedSeverity(e.target.value)}
                    className="w-full p-1 bg-white border border-[#c4c3bb] rounded text-xs focus:outline-none"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] font-bold text-[#55554f] uppercase tracking-wider block">Policy Mappings</span>
                  <select 
                    value={selectedFramework}
                    onChange={(e) => setSelectedFramework(e.target.value)}
                    className="w-full p-1 bg-white border border-[#c4c3bb] rounded text-xs focus:outline-none"
                  >
                    <option value="ALL">All Frameworks</option>
                    <option value="PCI DSS">PCI DSS v4.0</option>
                    <option value="CIS">CIS Benchmark</option>
                    <option value="GDPR">GDPR Art 32</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] font-bold text-[#55554f] uppercase tracking-wider block">Target Namespace</span>
                  <select 
                    value={selectedNamespace}
                    onChange={(e) => setSelectedNamespace(e.target.value)}
                    className="w-full p-1 bg-white border border-[#c4c3bb] rounded text-xs focus:outline-none"
                  >
                    <option value="ALL">All Namespaces</option>
                    <option value="payments">payments</option>
                    <option value="billing">billing</option>
                    <option value="monitoring">monitoring</option>
                  </select>
                </div>
              </div>

              {/* LIST MATRIX TABLE */}
              <div className="bg-white rounded-lg border border-[#e2e2d9] shadow-xs overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-[#e2e2d9] text-[#70706a] bg-[#faf9f6] uppercase font-bold">
                        <th className="p-3 px-4">Severity</th>
                        <th className="p-3 px-4">ID Code</th>
                        <th className="p-3 px-4">Workload Finding Specification</th>
                        <th className="p-3 px-4">Cluster Context</th>
                        <th className="p-3 px-4">Namespace Target</th>
                        <th className="p-3 px-4">Resource Target Path</th>
                        <th className="p-2">Standards</th>
                        <th className="p-3 px-4">Status</th>
                        <th className="p-3 px-4 text-right">Action SRE</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#f5f5f0]">
                      {filteredViolationsList.length === 0 ? (
                        <tr>
                          <td colSpan={9} className="p-12 text-center text-slate-500 font-bold">No active resource matching found query. Try clearing filters.</td>
                        </tr>
                      ) : (
                        filteredViolationsList.map((v) => (
                          <tr key={v.id} className="hover:bg-[#faf9f6]/95 transition-all">
                            <td className="p-3 px-4">
                              <span className="bg-red-50 text-red-800 px-2 py-0.5 rounded font-bold border border-red-200">
                                {v.severity}
                              </span>
                            </td>
                            <td className="p-3 px-4 font-mono font-bold text-zinc-950">{v.ruleId}</td>
                            <td className="p-3 px-4 font-bold text-zinc-900">{v.finding}</td>
                            <td className="p-3 px-4 font-mono text-zinc-500">{v.cluster}</td>
                            <td className="p-3 px-4">
                              <span className="bg-blue-50 text-blue-800 border border-blue-200 font-mono px-2 py-0.2 rounded font-bold text-[11px]">
                                {v.namespace}
                              </span>
                            </td>
                            <td className="p-3 px-4 font-mono text-zinc-500 italic">{v.resource}</td>
                            <td className="p-3 px-4 text-xs font-bold">{v.framework}</td>
                            <td className="p-3 px-4 font-bold text-amber-800">● {v.status}</td>
                            <td className="p-3 px-4 text-right">
                              <button 
                                onClick={() => triggerViolationRemediation(v)}
                                className="bg-[#f0ede6] text-black hover:text-white hover:bg-black p-1 px-3 rounded font-bold"
                              >
                                Audit Remediation
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* VIOLATION ACTIVE DRAWER - remediation & technical sources drawers */}
              {activeViolation && (
                <div className="bg-[#faf9f6] border-2 border-[#1c1c1a] rounded-lg p-6 space-y-5 shadow-md animate-fadeIn">
                  <div className="flex justify-between items-start border-b border-[#dfded6] pb-3">
                    <div>
                      <span className="bg-red-200 text-red-900 font-bold font-mono px-2 rounded mb-1 inline-block text-[10px] uppercase">
                        {activeViolation.severity} Compliance Violation Block
                      </span>
                      <h3 className="text-base font-extrabold text-zinc-950">{activeViolation.finding} (Reference rule: {activeViolation.ruleId})</h3>
                      <p className="text-[11px] text-[#55554f]">Located cluster context: <strong>{activeViolation.cluster}</strong>  |  Target namespace group: <code className="bg-[#dfded6] px-1 font-mono">{activeViolation.namespace}</code></p>
                    </div>
                    <button onClick={() => setActiveViolation(null)} className="bg-[#1c1c1a] text-white p-1 rounded hover:bg-black">
                      <X className="h-4 w-4" />
                    </button>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    
                    {/* Directions columns */}
                    <div className="space-y-4">
                      <div>
                        <h4 className="text-[10px] font-bold text-[#70706a] uppercase">Risk Overview Description</h4>
                        <p className="text-xs bg-white p-3 rounded border border-[#dfded6] text-zinc-950 mt-1 leading-relaxed">
                          {activeViolation.description}
                        </p>
                      </div>

                      <div className="p-4 bg-emerald-50 rounded border border-emerald-200 space-y-1.5">
                        <h4 className="text-xs font-bold text-emerald-900 uppercase flex items-center gap-1.5">
                          <Check className="h-4 w-4 text-emerald-600 stroke-[3]" />
                          Red Hat OpenShift Target Remediation Specs
                        </h4>
                        <p className="text-xs font-mono bg-white p-2 border border-emerald-100 text-zinc-900 rounded">
                          {activeViolation.remediation}
                        </p>
                      </div>
                    </div>

                    {/* Metadata & expandable technical details drawer */}
                    <div className="space-y-4">
                      <div className="bg-white p-4 rounded border border-[#dfded6] space-y-3 text-xs">
                        <h4 className="text-[10px] font-bold uppercase text-[#70706a]">Exception Integration Dispatcher</h4>
                        <p className="text-[#60605c] leading-relaxed text-[11px]">
                          Need transient bypass for regulatory compliance? Push a policy exception token directly into SRE configs.
                        </p>
                        <button 
                          onClick={() => {
                            setCurrentPage('admin');
                            setAdminActiveTab('exceptions');
                            setNewExpRule(activeViolation.ruleId);
                            setNewExpNamespace(activeViolation.namespace);
                            setNewExpReason(`Temporary bypass required during deployment updates: ${activeViolation.finding}`);
                            setActiveViolation(null);
                          }}
                          className="w-full bg-amber-500 hover:bg-amber-600 text-black py-1.5 rounded font-bold flex items-center justify-center gap-1.5 uppercase tracking-wide text-[10px]"
                        >
                          <Bookmark className="h-3.5 w-3.5" />
                          Apply Policy Exception Rules
                        </button>
                      </div>

                      {/* TECHNICAL DETAILS DRAWER - Keep tools hidden behind Technical Details */}
                      <div className="border border-[#dfded6] rounded bg-[#fcfbfa]">
                        <button 
                          onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                          className="w-full p-3 bg-[#f1f0ea] hover:bg-[#e4e3dc] transition-all text-xs font-bold flex justify-between items-center text-[#1c1c1a]"
                        >
                          <span className="flex items-center gap-1.5">
                            <Terminal className="h-4 w-4 text-gray-500" />
                            Technical Details / Evidence Drawer
                          </span>
                          <span className="text-[10px] font-mono tracking-wider text-amber-900 font-extrabold">
                            {showTechnicalDetails ? 'COLLAPSE VENDOR' : 'EXPAND VENDOR CODE'}
                          </span>
                        </button>

                        {showTechnicalDetails && (
                          <div className="p-4 bg-white border-t border-[#dfded6] text-[11px] space-y-3 animate-fadeIn">
                            <div className="bg-red-50 p-2 border border-red-100 rounded font-mono text-xs text-red-900 leading-relaxed">
                              <p className="text-[9px] text-[#70706a] uppercase font-bold block mb-1">Decrypted Auditor Signal Digest</p>
                              {activeViolation.evidenceDigest}
                            </div>
                            <div>
                              <p className="text-[9px] text-[#70706a] uppercase font-bold block">Evaluation Scanner Engines:</p>
                              <div className="flex gap-2 pt-1 font-semibold text-zinc-900">
                                {activeViolation.scanners.map((sc, idx) => (
                                  <span key={idx} className="bg-[#faf9f6]/95 border border-[#dfded6] p-0.5 px-2 rounded">✓ {sc}</span>
                                ))}
                              </div>
                            </div>
                            <div>
                              <p className="text-[9px] text-[#70706a] uppercase font-bold block">Raw Rule IDs Evaluation Parameters:</p>
                              <div className="flex gap-1.5 pt-1">
                                {activeViolation.rawRules.map((rw, idx) => (
                                  <code key={idx} className="bg-[#1c1c1a] text-amber-400 p-0.5 px-2 rounded font-mono text-xs">{rw}</code>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>

                    </div>

                  </div>
                </div>
              )}

            </div>
          )}

          {/* ==================== 4. SCENE: AUDITOR EVIDENCE PACKS ==================== */}
          {currentPage === 'evidence' && (
            <div className="space-y-6">
              
              <div>
                <h2 className="text-lg font-bold text-[#1c1c1a]">Auditor Evidence Packs Collection</h2>
                <p className="text-sm text-[#70706a]">Download formal evidential data artifacts configured specifically to prove standard regulatory compliance.</p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* PDF evidence logs lists */}
                <div className="lg:col-span-2 space-y-3.5 animate-fadeIn">
                  <div className="bg-white rounded-lg border border-[#e2e2d9] shadow-xs overflow-hidden">
                    <div className="p-4 bg-[#faf9f6] border-b border-[#e2e2d9] text-[10px] font-bold text-[#70706a] uppercase">Generated Evidence Record Artifacts</div>
                    <div className="divide-y divide-[#f5f5f0]">
                      {evidencePacks.map((pack) => (
                        <div 
                          key={pack.id}
                          onClick={() => setActiveEvidence(pack)}
                          className={`p-4 cursor-pointer transition-all hover:bg-[#faf9f6] flex justify-between items-center ${activeEvidence?.id === pack.id ? 'bg-amber-50/75 border-l-4 border-amber-500' : ''}`}
                        >
                          <div>
                            <span className="bg-emerald-50 text-emerald-800 text-[9px] font-bold px-1.5 py-0.2 rounded border border-emerald-200">CRYPTOGRAPHIC COMPLIANT</span>
                            <h4 className="text-sm font-extrabold text-[#1c1c1a] mt-1.5">{pack.framework} ({pack.profile})</h4>
                            <p className="text-xs text-[#70706a] mt-0.5">Scan context: <strong>{pack.cluster}</strong> | evaluated on: {pack.scanDate}</p>
                          </div>
                          <div className="text-right">
                            <span className="text-[10px] text-[#70706a] block">Controls Evaluized</span>
                            <span className="font-mono font-bold text-[#1c1c1a]">{pack.passed} / {pack.evaluated} Correct</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Details pane showing details side panel */}
                <div className="space-y-4">
                  <div className="bg-white rounded-lg border border-[#e2e2d9] p-5 shadow-xs space-y-4">
                    {activeEvidence ? (
                      <div className="space-y-4 animate-fadeIn">
                        <div className="border-b border-[#dfded6] pb-3">
                          <span className="text-[9px] font-bold text-[#70706a] uppercase">Record Metadata</span>
                          <h3 className="text-sm font-bold text-[#1c1c1a] mt-1">{activeEvidence.framework}</h3>
                          <p className="text-xs text-[#60605c]">Cluster baseline file profile: <strong>{activeEvidence.profile}</strong></p>
                        </div>

                        <div className="grid grid-cols-2 gap-3 text-xs">
                          <div className="bg-[#faf9f6] p-2 rounded border border-[#dfded6]">
                            <span className="text-zinc-500 block text-[9px]">Passed Checks</span>
                            <span className="text-sm font-bold text-emerald-800 font-mono">{activeEvidence.passed}</span>
                          </div>
                          <div className="bg-[#faf9f6] p-2 rounded border border-[#dfded6]">
                            <span className="text-zinc-500 block text-[9px]">Failed Gaps</span>
                            <span className="text-sm font-bold text-red-800 font-mono">{activeEvidence.failed}</span>
                          </div>
                        </div>

                        {/* Download parameters formats */}
                        <div className="space-y-2">
                          <span className="text-[10px] font-bold text-[#70706a] uppercase block">Evidence PDF / JSON download links</span>
                          <div className="space-y-1.5">
                            {activeEvidence.downloadFormats.map((df, idx) => (
                              <button 
                                key={idx}
                                onClick={() => alert(`Retrieving cryptographic key authorization parameters for physical download of: ${df.format}`)}
                                className="w-full flex justify-between items-center bg-[#f5f5f0] hover:bg-[#e4e3dc] p-2 border border-[#dfded6] rounded text-xs font-semibold transition-colors"
                              >
                                <span className="flex items-center gap-1 text-slate-800">
                                  <Download className="h-3.5 w-3.5" />
                                  {df.format}
                                </span>
                                <span className="text-[10px] bg-white border px-1 rounded font-mono">{df.size}</span>
                              </button>
                            ))}
                          </div>
                        </div>

                        {/* Scanner references hidden inside technical detail box */}
                        <div className="border border-[#dfded6] rounded bg-[#faf9f6] overflow-hidden text-xs">
                          <div className="bg-[#f1f0ea] p-2 border-b border-[#dfded6] font-bold uppercase text-[9px] text-[#70706a]">
                            Technical Evidence Sources
                          </div>
                          <div className="p-3 space-y-1 text-[#5c5c56]">
                            <p className="text-[9px] italic mb-1">Evaluated via raw scanner feeds:</p>
                            {activeEvidence.scannersUsed.map((sc, idx) => (
                              <div key={idx} className="flex items-center gap-1 bg-white p-1 rounded border border-[#dfded6] font-mono text-[10px]">
                                <span className="h-1 w-1 bg-emerald-600 rounded-full"></span>
                                {sc}
                              </div>
                            ))}
                          </div>
                        </div>

                      </div>
                    ) : (
                      <div className="py-12 text-center text-slate-400 space-y-2">
                        <FileText className="h-10 w-10 mx-auto text-slate-300" />
                        <p className="font-bold text-sm">Select Evidence record</p>
                        <p className="text-[11px]">Click on any row record in the evidence container list to inspect metrics details or evaluate PDFs.</p>
                      </div>
                    )}
                  </div>
                </div>

              </div>

            </div>
          )}

          {/* ==================== 5. SCENE: CLUSTERS PLATFORM MAPS ==================== */}
          {currentPage === 'clusters' && (
            <div className="space-y-6">
              
              <div>
                <h2 className="text-lg font-bold text-[#1c1c1a]">OpenShift Cluster Configuration Topology</h2>
                <p className="text-sm text-[#70706a]">Unified architecture navigating from physical Clusters down to Namespaces, Host Nodes and Workers.</p>
              </div>

              {/* Cards row overview */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-fadeIn">
                {clusters.map((c) => (
                  <div 
                    key={c.id}
                    onClick={() => { setActiveCluster(c); setActiveBreadcrumb(['Compliance Dashboard', c.id]); }}
                    className={`p-5 rounded-lg border cursor-pointer transition-all ${activeCluster?.id === c.id ? 'bg-white border-[#1c1c1a] ring-2 ring-[#1c1c1a] shadow-xs' : 'bg-white border-[#dfded6] hover:border-[#1c1c1a]'}`}
                  >
                    <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-wide block">Active continuous scan telemetry</span>
                    <h3 className="text-xl font-extrabold text-[#1c1c1a] mt-2">{c.id}</h3>
                    
                    <div className="grid grid-cols-3 gap-1 pt-3.5 mt-3.5 border-t border-[#f5f5f0] text-xs">
                      <div>
                        <span className="text-zinc-500 block text-[9px]">OCP VER</span>
                        <span className="font-mono font-bold text-[#1c1c1a]">{c.version}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block text-[9px]">NAMESPACES</span>
                        <span className="font-bold font-mono text-[#1c1c1a]">{c.namespaces}</span>
                      </div>
                      <div>
                        <span className="text-zinc-500 block text-[9px]">COMPLIANT</span>
                        <span className="font-bold text-emerald-800">{c.complianceScore}%</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Cluster Detail Drilldown - contains Namespace Table and Node Table specifically */}
              {activeCluster ? (
                <div className="bg-white rounded-lg border border-[#e2e2d9] p-6 space-y-4 shadow-xs animate-fadeIn">
                  
                  <div className="flex justify-between items-center border-b border-[#dfded6] pb-3 flex-wrap gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-zinc-950">Cluster Evaluation: {activeCluster.id} ({activeCluster.version})</h3>
                      <p className="text-xs text-slate-500">Continuous inspection mapping mapping profiles across machine layers.</p>
                    </div>

                    <div className="flex gap-1 bg-[#f0ede6] p-1 rounded">
                      <button 
                        onClick={() => setActiveClusterTab('namespaces')}
                        className={`text-xs p-1 px-3.5 rounded font-bold transition-all ${activeClusterTab === 'namespaces' ? 'bg-[#1c1c1a] text-white' : 'text-zinc-700 hover:bg-[#e4e3dc]'}`}
                      >
                        Namespaces Matrix ({NAMESPACES_DATA[activeCluster.id]?.length || 0})
                      </button>
                      <button 
                        onClick={() => setActiveClusterTab('nodes')}
                        className={`text-xs p-1 px-3.5 rounded font-bold transition-all ${activeClusterTab === 'nodes' ? 'bg-[#1c1c1a] text-white' : 'text-zinc-700 hover:bg-[#e4e3dc]'}`}
                      >
                        Physical Host Nodes
                      </button>
                    </div>
                  </div>

                  {/* ACTIVE TAB: NAMESPACES */}
                  {activeClusterTab === 'namespaces' && (
                    <div className="space-y-4 animate-fadeIn">
                      <div className="p-3 bg-blue-50 text-blue-900 rounded border border-blue-200 text-xs flex items-center gap-1.5">
                        <Info className="h-4 w-4" />
                        <span>Workloads are evaluated mapped strictly within Namespaces. Click namespace filters in the left pane to analyze regulatory requirements.</span>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs border-collapse">
                          <thead>
                            <tr className="border-b border-[#dfded6] pb-2 text-[#70706a] uppercase font-bold bg-[#faf9f6]">
                              <th className="p-2">Namespace Name Target</th>
                              <th className="p-2">Assigned Owner Group Team</th>
                              <th className="p-2">Monitored Pod Workloads</th>
                              <th className="p-2">Compliance Score</th>
                              <th className="p-2 text-right">Open Findings Matrix</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-[#f5f5f0]">
                            {(NAMESPACES_DATA[activeCluster.id] || []).map((ns, idx) => (
                              <tr key={idx} className="hover:bg-[#faf9f6]/95 transition-all">
                                <td className="p-2.5 font-mono">
                                  <button 
                                    onClick={() => { setSelectedNamespace(ns.name); setCurrentPage('violations'); }}
                                    className="text-xs bg-blue-50 hover:underline border border-blue-100 text-blue-800 p-0.5 px-2 rounded font-bold"
                                  >
                                    {ns.name}
                                  </button>
                                </td>
                                <td className="p-2.5 font-semibold text-zinc-900">{ns.team}</td>
                                <td className="p-2.5 font-mono text-gray-500">{ns.workloads} payloads</td>
                                <td className="p-2.5 font-bold text-emerald-800">{ns.complianceScore}% Compliant</td>
                                <td className="p-2.5 text-right">
                                  {ns.openFindings > 0 ? (
                                    <span className="bg-red-50 text-red-000 border border-red-200 px-2.5 py-0.5 rounded font-mono font-bold text-red-800">{ns.openFindings} failures</span>
                                  ) : (
                                    <span className="text-emerald-800 font-bold">✓ Clean Baseline</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* ACTIVE TAB: PHYSICAL NODES */}
                  {activeClusterTab === 'nodes' && (
                    <div className="overflow-x-auto animate-fadeIn">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-[#dfded6] pb-2 text-[#70706a] uppercase font-bold bg-[#faf9f6]">
                            <th className="p-2">Machine Node Target Name ID</th>
                            <th className="p-2">Cluster Role Position</th>
                            <th className="p-2">Node Host OS (Operating System)</th>
                            <th className="p-2">Compliance Hardening Weight</th>
                            <th className="p-2 text-right">Failing Hardening Daemon Rules</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#f5f5f0]">
                          {(NODES_DATA[activeCluster.id] || []).map((nd, idx) => (
                            <tr key={idx} className="hover:bg-[#faf9f6]/95 transition-all">
                              <td className="p-2.5 font-mono font-bold text-zinc-900">{nd.name}</td>
                              <td className="p-2.5 text-gray-500 font-semibold">{nd.role}</td>
                              <td className="p-2.5 italic text-zinc-700 font-semibold">{nd.os}</td>
                              <td className="p-2.5 font-bold font-mono text-emerald-800">{nd.complianceScore}%</td>
                              <td className="p-2.5 text-right">
                                {nd.failedRules > 0 ? (
                                  <span className="text-red-705 bg-red-50 border border-red-200 p-0.5 px-2 rounded font-bold font-mono text-red-800">{nd.failedRules} failures</span>
                                ) : (
                                  <span className="bg-emerald-50 text-emerald-800 border border-emerald-100 p-0.5 px-2 rounded font-bold">✓ Fully Hardened</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                </div>
              ) : (
                <div className="bg-white p-12 text-center text-slate-400 border rounded-lg animate-fadeIn">
                  <Server className="h-10 w-10 text-slate-300 mx-auto" />
                  <p className="font-bold text-sm mt-2">Select Cluster context</p>
                  <p className="text-xs">Click one of the active clusters above to drill down to Namespace logical workloads and host Node OS hardening metrics.</p>
                </div>
              )}

            </div>
          )}

          {/* ==================== 6. SCENE: SECURITY ADMINISTRATION ==================== */}
          {currentPage === 'admin' && (
            <div className="space-y-6 animate-fadeIn">

              {/* Sub navbar tabs */}
              <div className="flex border-b border-[#dfded6] gap-4">
                <button 
                  onClick={() => setAdminActiveTab('exceptions')}
                  className={`pb-2.5 text-xs font-bold border-b-2 transition-all ${adminActiveTab === 'exceptions' ? 'border-zinc-950 text-zinc-950 font-extrabold' : 'border-transparent text-gray-500'}`}
                >
                  Manage Security Exceptions ({exceptions.length})
                </button>
                <button 
                  onClick={() => setAdminActiveTab('profiles')}
                  className={`pb-2.5 text-xs font-bold border-b-2 transition-all ${adminActiveTab === 'profiles' ? 'border-zinc-950 text-zinc-950 font-extrabold' : 'border-transparent text-gray-500'}`}
                >
                  Active Scan Profile Schedules
                </button>
                <button 
                  onClick={() => setAdminActiveTab('integrations')}
                  className={`pb-2.5 text-xs font-bold border-b-2 transition-all ${adminActiveTab === 'integrations' ? 'border-zinc-950 text-zinc-950 font-extrabold' : 'border-transparent text-gray-500'}`}
                >
                  SSO & Pipeline Integrations
                </button>
              </div>

              {/* EXCEPTIONS POLICY TAB */}
              {adminActiveTab === 'exceptions' && (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 animate-fadeIn">
                  
                  {/* Create Exception policy */}
                  <div className="lg:col-span-4 bg-white p-6 rounded border border-[#dfded6] shadow-xs space-y-3.5 h-fit">
                    <h3 className="text-xs font-extrabold uppercase tracking-wide text-zinc-70s hover:text-[#1c1c1a]">Compile Security Exception</h3>
                    <p className="text-[11px] text-[#70706a]">Transient allowance for specific rules. Exceptions register on standard compliance audits.</p>
                    
                    {formSuccessMsg && (
                      <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs p-2.5 rounded font-bold">
                        {formSuccessMsg}
                      </div>
                    )}

                    <form onSubmit={handleCreateException} className="space-y-3">
                      <div className="space-y-1">
                        <span className="text-[10px] font-bold uppercase text-zinc-500 block">Failing Rule ID Code</span>
                        <input 
                          type="text" 
                          placeholder="e.g. CIS-5.2.5" 
                          value={newExpRule}
                          onChange={(e) => setNewExpRule(e.target.value)}
                          className="w-full text-xs p-2 bg-white border rounded border-[#dfded6] focus:outline-none"
                        />
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] font-bold uppercase text-zinc-500 block">Target Namespace Target</span>
                        <select 
                          value={newExpNamespace}
                          onChange={(e) => setNewExpNamespace(e.target.value)}
                          className="w-full text-xs p-2 bg-white border rounded border-[#dfded6]"
                        >
                          <option value="payments">payments</option>
                          <option value="billing">billing</option>
                          <option value="monitoring">monitoring</option>
                        </select>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] font-bold uppercase text-zinc-500 block">Justification Reason Justification</span>
                        <textarea 
                          placeholder="Provide audit-trail compliance reasoning..." 
                          rows={3} 
                          value={newExpReason}
                          onChange={(e) => setNewExpReason(e.target.value)}
                          className="w-full text-xs p-2 bg-white border rounded border-[#dfded6] focus:outline-none"
                        />
                      </div>

                      <div className="space-y-1">
                        <span className="text-[10px] font-bold uppercase text-zinc-500 block">Expiry window limit</span>
                        <input 
                          type="date" 
                          value={newExpExpiry}
                          onChange={(e) => setNewExpExpiry(e.target.value)}
                          className="w-full text-xs p-2 bg-white border rounded border-[#dfded6]"
                        />
                      </div>

                      <button 
                        type="submit" 
                        className="w-full bg-[#1c1c1a] text-white hover:bg-black p-2 rounded text-xs font-extrabold flex justify-center items-center gap-1.5 uppercase transition-all"
                      >
                        <Plus className="h-4 w-4" />
                        Compile Exception Policy
                      </button>
                    </form>
                  </div>

                  {/* Exceptions listings */}
                  <div className="lg:col-span-8 bg-white p-6 rounded border border-[#dfded6] shadow-xs space-y-3.5">
                    <h4 className="text-xs uppercase font-extrabold text-[#70706a]">Active Security Exemption Rules Mappings</h4>
                    <div className="overflow-x-auto font-sans">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-[#dfded6] pb-2 text-zinc-500 uppercase font-bold bg-[#faf9f6]">
                            <th className="p-2">Rule Code</th>
                            <th className="p-2">Namespace Target</th>
                            <th className="p-2">Auditing Justification Purpose</th>
                            <th className="p-2">Expires</th>
                            <th className="p-2 text-right">Action SRE</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#f5f5f0]">
                          {exceptions.map((ex) => (
                            <tr key={ex.id} className="hover:bg-[#faf9f6]/95 transition-all">
                              <td className="p-2.5 font-mono">
                                <span className="bg-red-50 text-red-900 border border-red-200 px-2 py-0.5 rounded font-bold font-mono">
                                  {ex.ruleId}
                                </span>
                              </td>
                              <td className="p-2.5">
                                <span className="bg-blue-50 text-blue-800 border border-blue-200 text-xs font-mono font-bold px-2.5 py-0.2 rounded">
                                  {ex.namespace}
                                </span>
                              </td>
                              <td className="p-2.5 text-[11px] text-[#55554f] max-w-xs leading-relaxed italic">
                                "{ex.reason}"
                              </td>
                              <td className="p-2.5 text-zinc-900 font-bold font-mono text-[11px]">{ex.expires}</td>
                              <td className="p-2.5 text-right">
                                <button 
                                  onClick={() => { handleDeleteException(ex.id); alert(`Revoking authorization metadata for rule ${ex.ruleId}. Policy compiling...`); }}
                                  className="text-red-700 bg-red-50 hover:bg-red-100 p-1 px-2.5 rounded font-bold border border-red-200 inline-flex items-center gap-1 transition-all"
                                >
                                  <Trash className="h-3 w-3" />
                                  Revoke Policy
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                </div>
              )}

              {/* TIMED SCANNING PROFILES SCHEDULES */}
              {adminActiveTab === 'profiles' && (
                <div className="bg-white rounded-lg border border-[#e2e2d9] p-6 space-y-4 shadow-xs animate-fadeIn">
                  <div>
                    <h3 className="text-sm font-bold text-zinc-950">Active Monitored Profiles Schedules</h3>
                    <p className="text-xs text-[#70706a]">Scanner instances dispatched directly to node controllers.</p>
                  </div>
                  <div className="overflow-x-auto text-xs">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-[#dfded6] pb-2 text-zinc-500 font-bold uppercase bg-[#faf9f6]">
                          <th className="p-2">Profile ID Code</th>
                          <th className="p-2">Target Framework standards</th>
                          <th className="p-2">Auto Dispatch Timeline</th>
                          <th className="p-2">Active Monitored Clusters</th>
                          <th className="p-2 text-right">Daemon Operator State</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#f5f5f0]">
                        <tr className="hover:bg-[#faf9f6]">
                          <td className="p-3 font-mono font-bold text-[#1c1c1a]">ocp4-cis</td>
                          <td className="p-3 font-semibold text-zinc-900">CIS OpenShift Benchmark</td>
                          <td className="p-3 font-medium">Hourly Sweep Checks</td>
                          <td className="p-3 font-bold">8 Clusters</td>
                          <td className="p-3 text-right">
                            <span className="text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded font-extrabold inline-flex items-center gap-1">
                              <span className="h-2 w-2 bg-emerald-500 rounded-full"></span>
                              Active Dispatches
                            </span>
                          </td>
                        </tr>
                        <tr className="hover:bg-[#faf9f6]">
                          <td className="p-3 font-mono font-bold text-[#1c1c1a]">ocp4-pci-dss</td>
                          <td className="p-3 font-semibold text-zinc-900">PCI DSS v4.0 Suite</td>
                          <td className="p-3 font-medium">Daily Sweep Checks</td>
                          <td className="p-3 font-bold">5 Clusters</td>
                          <td className="p-3 text-right">
                            <span className="text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded font-extrabold inline-flex items-center gap-1">
                              <span className="h-2 w-2 bg-emerald-500 rounded-full"></span>
                              Active Dispatches
                            </span>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* INTEGRATIONS FEEDS TAB */}
              {adminActiveTab === 'integrations' && (
                <div className="bg-white p-6 rounded border border-[#dfded6] shadow-xs space-y-4 animate-fadeIn">
                  <h3 className="text-sm font-extrabold text-zinc-950">SSO & SRE Webhook pipeline mappings</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {integrations.map((itm) => (
                      <div key={itm.id} className="p-4 bg-[#faf9f6] border border-[#dfded6] rounded-lg flex flex-col justify-between space-y-3 shadow-xs">
                        <div>
                          <span className="bg-white p-0.5 px-2 rounded tracking-wide border border-[#dfded6] text-[10px] font-bold text-[#70706a] uppercase block w-fit">
                            {itm.category}
                          </span>
                          <h4 className="text-xs font-bold text-zinc-950 mt-2">{itm.name}</h4>
                          <span className="font-mono text-[11px] block mt-1 text-slate-500">Synced: {itm.lastSync}</span>
                        </div>

                        <div className="flex justify-between items-center pt-2.5 border-t border-[#f5f5f0]">
                          <span className={`text-[11px] font-bold ${itm.status === 'Connected' ? 'text-emerald-800' : 'text-[#70706a]'}`}>● {itm.status}</span>
                          <button 
                            onClick={() => { syncIntegration(itm.id); alert(`Synchronized connection status instantly: ${itm.name}`); }}
                            className="bg-white hover:bg-zinc-100 border border-[#dfded6] p-1 px-2.5 rounded font-extrabold transition-all"
                          >
                            Toggle Engine
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          )}

        </div>

        {/* COMPREHENSIVE FOOTER */}
        <footer className="p-6 border-t border-[#dfded6] bg-[#f1f0ea] text-[11px] text-[#70706a] flex flex-col sm:flex-row items-center justify-between gap-4 mt-auto">
          <div>
            <p className="font-bold text-[#1c1c1a]">Red Hat OpenShift Enterprise Compliance Audit Cockpit</p>
            <p className="text-[#55554f]">Continuous auditing with integrated SHA-256 evidence signatures & strict SCC namespace filters.</p>
          </div>
          <div>
            <span className="bg-emerald-500/10 text-emerald-800 border border-emerald-200 font-mono text-[10px] uppercase font-bold px-3 py-1 rounded">
              ✓ AUDITOR BLOCKCHAIN SIGNATURE SEALS COMPLIANT
            </span>
          </div>
        </footer>

      </main>

    </div>
  );
}
