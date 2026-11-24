import crypto from 'node:crypto';
import { CONTROL_SEVERITY } from './standards.js';

/**
 * Prioritizes remediation actions based on evaluation findings.
 * @param {Object} evalResult - The result returned from evaluateEnvironment
 * @returns {Object} Structured remediation roadmap with prioritized phases
 */
export function generateRemediationRoadmap(evalResult) {
  if (!evalResult || !Array.isArray(evalResult.findings)) {
    throw new TypeError('Invalid evaluation result: findings array required');
  }

  const p1Immediate = [];
  const p2Standard = [];
  const p3Scheduled = [];
  const decommissioningTasks = [];

  for (const finding of evalResult.findings) {
    const task = {
      controlId: finding.controlId,
      severity: finding.severity,
      action: finding.title,
      rationale: finding.detail
    };

    if (finding.title.includes('End-of-Life') || finding.title.includes('Unsupported')) {
      decommissioningTasks.push({
        ...task,
        target: finding.title.replace('Unsupported / End-of-Life OS Detected: ', ''),
        recommendation: 'Isolate host, snapshot state, migrate workloads to supported LTS release, and decommission legacy node.'
      });
    }

    if (finding.severity === CONTROL_SEVERITY.CRITICAL) {
      p1Immediate.push({
        ...task,
        slaWindowHours: 24,
        category: 'IMMEDIATE_RISK_MITIGATION'
      });
    } else if (finding.severity === CONTROL_SEVERITY.HIGH) {
      p2Standard.push({
        ...task,
        slaWindowDays: 7,
        category: 'BASELINE_ALIGNMENT'
      });
    } else {
      p3Scheduled.push({
        ...task,
        slaWindowDays: 30,
        category: 'HYGIENE_OPTIMIZATION'
      });
    }
  }

  const totalActions = p1Immediate.length + p2Standard.length + p3Scheduled.length;

  return {
    environmentId: evalResult.environmentId,
    generatedAt: new Date().toISOString(),
    currentComplianceScore: evalResult.complianceScore,
    projectedComplianceScore: 100,
    totalActionCount: totalActions,
    decommissioningCount: decommissioningTasks.length,
    roadmap: {
      phase1_immediate_24h: p1Immediate,
      phase2_standard_7d: p2Standard,
      phase3_scheduled_30d: p3Scheduled,
      decommissioning: decommissioningTasks
    }
  };
}

/**
 * Creates verifiable evidence payload with cryptographic digest.
 * @param {Object} evalResult - Evaluation result
 * @param {Object} roadmap - Remediation roadmap
 * @returns {Object} Verifiable evidence document
 */
export function buildDeliveryEvidence(evalResult, roadmap) {
  const payload = {
    environmentId: evalResult.environmentId,
    evaluatedAt: evalResult.evaluatedAt,
    complianceScore: evalResult.complianceScore,
    status: evalResult.status,
    findingsSummary: {
      total: evalResult.findingsCount,
      critical: evalResult.criticalCount,
      high: evalResult.highCount
    },
    domainScores: evalResult.domainScores,
    pendingActionCount: roadmap.totalActionCount,
    decommissioningRequired: roadmap.decommissioningCount > 0
  };

  const digest = crypto
    .createHash('sha256')
    .update(JSON.stringify(payload))
    .digest('hex');

  return {
    ...payload,
    evidenceDigest: `sha256:${digest}`,
    certifiedBy: 'infra-integration-assurance-engine/v1.0.0'
  };
}
