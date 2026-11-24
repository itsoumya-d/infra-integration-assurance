import { BASELINE_CONTROLS, CONTROL_SEVERITY, UNSUPPORTED_OS_PLATFORMS } from './standards.js';

/**
 * Evaluates an environment snapshot against integration baselines.
 * @param {Object} snapshot - Environment snapshot containing hosts, backup, security, and iam state
 * @returns {Object} Evaluation result containing score, findings, and compliance breakdown
 */
export function evaluateEnvironment(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') {
    throw new TypeError('Invalid environment snapshot: object required');
  }

  const findings = [];
  const domainScores = {};
  let totalAchievedWeight = 0;
  let totalPossibleWeight = 0;

  // 1. Evaluate Backups
  const backupCtrl = BASELINE_CONTROLS.BACKUP_POLICY;
  totalPossibleWeight += backupCtrl.weight;
  const backupState = snapshot.backup || {};
  let backupDeductions = 0;

  if (!backupState.configured) {
    findings.push({
      controlId: backupCtrl.id,
      severity: backupCtrl.severity,
      title: 'Missing Backup Policy Configuration',
      detail: 'The environment does not have a registered automated backup policy.'
    });
    backupDeductions += 1.0;
  } else {
    if (backupState.hoursSinceLastSuccess > backupCtrl.maxHoursSinceLastSuccess) {
      findings.push({
        controlId: backupCtrl.id,
        severity: backupCtrl.severity,
        title: 'Backup Execution Overdue',
        detail: `Last successful backup was ${backupState.hoursSinceLastSuccess}h ago (threshold: ${backupCtrl.maxHoursSinceLastSuccess}h).`
      });
      backupDeductions += 0.6;
    }
    if (backupCtrl.requireOffsite && !backupState.offsiteReplicated) {
      findings.push({
        controlId: backupCtrl.id,
        severity: CONTROL_SEVERITY.HIGH,
        title: 'Offsite Backup Replication Disabled',
        detail: 'Backups are maintained locally only without secondary regional replication.'
      });
      backupDeductions += 0.4;
    }
  }
  const backupWeight = Math.max(0, backupCtrl.weight * (1.0 - Math.min(1.0, backupDeductions)));
  totalAchievedWeight += backupWeight;
  domainScores[backupCtrl.id] = Math.round((backupWeight / backupCtrl.weight) * 100);

  // 2. Evaluate Patching & OS Health
  const patchCtrl = BASELINE_CONTROLS.PATCH_HYGIENE;
  totalPossibleWeight += patchCtrl.weight;
  const hosts = Array.isArray(snapshot.hosts) ? snapshot.hosts : [];
  let patchDeductions = 0;

  if (hosts.length === 0) {
    findings.push({
      controlId: patchCtrl.id,
      severity: CONTROL_SEVERITY.MEDIUM,
      title: 'No Registered Hosts',
      detail: 'Environment snapshot does not declare any active host infrastructure.'
    });
    patchDeductions += 0.5;
  } else {
    let unpatchedCount = 0;
    let criticalCveCount = 0;
    let eolCount = 0;

    for (const host of hosts) {
      if ((host.daysSinceLastPatch || 0) > patchCtrl.maxDaysUnpatched) {
        unpatchedCount++;
      }
      if ((host.criticalCVEs || 0) > patchCtrl.maxCriticalCVEs) {
        criticalCveCount += host.criticalCVEs;
      }
      if (host.os && UNSUPPORTED_OS_PLATFORMS.has(host.os.toLowerCase())) {
        eolCount++;
        findings.push({
          controlId: patchCtrl.id,
          severity: CONTROL_SEVERITY.HIGH,
          title: `Unsupported / End-of-Life OS Detected: ${host.hostname || 'Unknown'}`,
          detail: `Host runs ${host.os}, which has exceeded vendor security support.`
        });
      }
    }

    if (unpatchedCount > 0) {
      findings.push({
        controlId: patchCtrl.id,
        severity: CONTROL_SEVERITY.HIGH,
        title: 'Hosts Overdue for Patching',
        detail: `${unpatchedCount} of ${hosts.length} hosts have not received security patches in >${patchCtrl.maxDaysUnpatched} days.`
      });
      patchDeductions += 0.4 * (unpatchedCount / hosts.length);
    }
    if (criticalCveCount > 0) {
      findings.push({
        controlId: patchCtrl.id,
        severity: CONTROL_SEVERITY.CRITICAL,
        title: 'Unremediated Critical CVEs',
        detail: `${criticalCveCount} critical vulnerability instances present across fleet.`
      });
      patchDeductions += 0.5;
    }
    if (eolCount > 0) {
      patchDeductions += 0.3 * (eolCount / hosts.length);
    }
  }
  const patchWeight = Math.max(0, patchCtrl.weight * (1.0 - Math.min(1.0, patchDeductions)));
  totalAchievedWeight += patchWeight;
  domainScores[patchCtrl.id] = Math.round((patchWeight / patchCtrl.weight) * 100);

  // 3. Evaluate Endpoint Protection (EDR/XDR)
  const edrCtrl = BASELINE_CONTROLS.ENDPOINT_PROTECTION;
  totalPossibleWeight += edrCtrl.weight;
  let edrDeductions = 0;

  if (hosts.length === 0) {
    edrDeductions += 0.5;
  } else {
    let missingEdrCount = 0;
    let staleDefCount = 0;

    for (const host of hosts) {
      const edr = host.endpointProtection || {};
      if (!edr.installed || !edr.serviceRunning) {
        missingEdrCount++;
      } else {
        if ((edr.definitionAgeHours || 0) > edrCtrl.maxHoursDefinitionLag) {
          staleDefCount++;
        }
        if (edrCtrl.requireTamperProtection && !edr.tamperProtectionEnabled) {
          findings.push({
            controlId: edrCtrl.id,
            severity: CONTROL_SEVERITY.MEDIUM,
            title: `Tamper Protection Inactive on ${host.hostname || 'Host'}`,
            detail: 'EDR agent does not have administrative tamper protection locked.'
          });
          edrDeductions += 0.1 / hosts.length;
        }
      }
    }

    if (missingEdrCount > 0) {
      findings.push({
        controlId: edrCtrl.id,
        severity: CONTROL_SEVERITY.CRITICAL,
        title: 'Missing or Inactive Endpoint Protection',
        detail: `${missingEdrCount} of ${hosts.length} hosts do not have an active EDR service.`
      });
      edrDeductions += 0.8 * (missingEdrCount / hosts.length);
    }
    if (staleDefCount > 0) {
      findings.push({
        controlId: edrCtrl.id,
        severity: CONTROL_SEVERITY.HIGH,
        title: 'Stale EDR Definitions',
        detail: `${staleDefCount} hosts have signature definitions older than ${edrCtrl.maxHoursDefinitionLag}h.`
      });
      edrDeductions += 0.3 * (staleDefCount / hosts.length);
    }
  }
  const edrWeight = Math.max(0, edrCtrl.weight * (1.0 - Math.min(1.0, edrDeductions)));
  totalAchievedWeight += edrWeight;
  domainScores[edrCtrl.id] = Math.round((edrWeight / edrCtrl.weight) * 100);

  // 4. Evaluate IAM
  const iamCtrl = BASELINE_CONTROLS.IDENTITY_ACCESS;
  totalPossibleWeight += iamCtrl.weight;
  const iamState = snapshot.iam || {};
  let iamDeductions = 0;

  if (iamCtrl.requireAdminMFA && !iamState.adminMFAEnforced) {
    findings.push({
      controlId: iamCtrl.id,
      severity: CONTROL_SEVERITY.CRITICAL,
      title: 'MFA Not Enforced for Administrative Accounts',
      detail: 'Privileged identity accounts can authenticate without multi-factor verification.'
    });
    iamDeductions += 0.7;
  }
  if ((iamState.staleAccountCount || 0) > 0) {
    findings.push({
      controlId: iamCtrl.id,
      severity: CONTROL_SEVERITY.MEDIUM,
      title: 'Stale User Accounts Present',
      detail: `${iamState.staleAccountCount} accounts inactive >${iamCtrl.maxInactiveDays} days remain active in directory.`
    });
    iamDeductions += 0.3;
  }
  const iamWeight = Math.max(0, iamCtrl.weight * (1.0 - Math.min(1.0, iamDeductions)));
  totalAchievedWeight += iamWeight;
  domainScores[iamCtrl.id] = Math.round((iamWeight / iamCtrl.weight) * 100);

  // 5. Evaluate Monitoring & Telemetry
  const monCtrl = BASELINE_CONTROLS.MONITORING_TELEMETRY;
  totalPossibleWeight += monCtrl.weight;
  const monState = snapshot.monitoring || {};
  let monDeductions = 0;

  if (monCtrl.requireHeartbeat && !monState.heartbeatActive) {
    findings.push({
      controlId: monCtrl.id,
      severity: CONTROL_SEVERITY.HIGH,
      title: 'Monitoring Heartbeat Missing',
      detail: 'Central telemetry hub does not detect active heartbeat pings from environment.'
    });
    monDeductions += 0.5;
  }
  if (monCtrl.requireSiemForwarding && !monState.siemForwardingActive) {
    findings.push({
      controlId: monCtrl.id,
      severity: CONTROL_SEVERITY.HIGH,
      title: 'Audit Logs Not Forwarding to SIEM',
      detail: 'System and authentication event streams are not being streamed to central SIEM collector.'
    });
    monDeductions += 0.5;
  }
  const monWeight = Math.max(0, monCtrl.weight * (1.0 - Math.min(1.0, monDeductions)));
  totalAchievedWeight += monWeight;
  domainScores[monCtrl.id] = Math.round((monWeight / monCtrl.weight) * 100);

  const complianceScore = Math.round((totalAchievedWeight / totalPossibleWeight) * 100);

  return {
    environmentId: snapshot.environmentId || 'unknown-env',
    evaluatedAt: new Date().toISOString(),
    complianceScore,
    status: complianceScore >= 85 ? 'COMPLIANT' : complianceScore >= 60 ? 'NEEDS_REMEDIATION' : 'NON_COMPLIANT',
    domainScores,
    findingsCount: findings.length,
    criticalCount: findings.filter(f => f.severity === CONTROL_SEVERITY.CRITICAL).length,
    highCount: findings.filter(f => f.severity === CONTROL_SEVERITY.HIGH).length,
    findings
  };
}
