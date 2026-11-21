import type { AppConfig } from '../config.js';

export type CheckStatus = 'pass' | 'fail' | 'needs_review';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type CategoryId = 'injection' | 'auth' | 'secrets' | 'deployment';
export type VerificationMethod = 'runtime-probe' | 'config-inspection' | 'static-scan' | 'artifact-review';

export interface CheckOutcome {
  status: CheckStatus;
  /** What is actually implemented (factual, one or two sentences). */
  implementation: string;
  explanation: string;
  /** Concrete observations the verdict is based on. */
  evidence: string[];
  remediation: string[];
}

export interface CheckContext {
  config: AppConfig;
  /** Directory holding the compiled/source backend files (`src` or `dist`). */
  backendSrcDir: string;
  /** Repository root, when the full repo is present (it is not on a backend-only deploy). */
  repoRoot: string;
  now: () => Date;
}

export interface CheckDefinition {
  id: number;
  key: string;
  category: CategoryId;
  title: string;
  /** Impact if this control were missing or broken. */
  severity: Severity;
  methods: VerificationMethod[];
  run(ctx: CheckContext): Promise<CheckOutcome>;
}

export interface CheckResult extends CheckOutcome {
  id: number;
  key: string;
  category: CategoryId;
  title: string;
  severity: Severity;
  methods: VerificationMethod[];
  verifiedAt: string;
}

export interface SecurityReport {
  generatedAt: string;
  environment: string;
  scope: string;
  summary: { pass: number; fail: number; needs_review: number; total: number };
  categories: { id: CategoryId; index: string; label: string }[];
  checks: CheckResult[];
  /** Controls that cannot be verified from inside the application and need a human. */
  manualReviewItems: string[];
}

export const CATEGORIES: SecurityReport['categories'] = [
  { id: 'injection', index: '01', label: 'Injection & Input' },
  { id: 'auth', index: '02', label: 'Authentication & Sessions' },
  { id: 'secrets', index: '03', label: 'Secrets & Tokens' },
  { id: 'deployment', index: '04', label: 'Deployment & Privacy' },
];
