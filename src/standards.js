/**
 * Standards and control definitions for environment integration assurance.
 */

export const CONTROL_SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW'
};

export const BASELINE_CONTROLS = {
  BACKUP_POLICY: {
    id: 'CTRL-BCK-01',
    name: 'Backup Policy & Execution',
    severity: CONTROL_SEVERITY.CRITICAL,
    weight: 25,
    maxHoursSinceLastSuccess: 24,
    requireOffsite: true
  },
  PATCH_HYGIENE: {
    id: 'CTRL-PTC-01',
    name: 'Patch Hygiene & Vulnerability Management',
    severity: CONTROL_SEVERITY.HIGH,
    weight: 20,
    maxDaysUnpatched: 30,
    maxCriticalCVEs: 0
  },
  ENDPOINT_PROTECTION: {
    id: 'CTRL-EDR-01',
    name: 'EDR/XDR Health & Definition Freshness',
    severity: CONTROL_SEVERITY.CRITICAL,
    weight: 25,
    maxHoursDefinitionLag: 48,
    requireTamperProtection: true
  },
  IDENTITY_ACCESS: {
    id: 'CTRL-IAM-01',
    name: 'Identity & Access Hygiene',
    severity: CONTROL_SEVERITY.HIGH,
    weight: 15,
    requireAdminMFA: true,
    maxInactiveDays: 90
  },
  MONITORING_TELEMETRY: {
    id: 'CTRL-MON-01',
    name: 'Central Monitoring & SIEM Forwarding',
    severity: CONTROL_SEVERITY.MEDIUM,
    weight: 15,
    requireHeartbeat: true,
    requireSiemForwarding: true
  }
};

export const UNSUPPORTED_OS_PLATFORMS = new Set([
  'windows-server-2003',
  'windows-server-2008',
  'windows-server-2008-r2',
  'windows-server-2012',
  'windows-server-2012-r2',
  'centos-6',
  'centos-7',
  'ubuntu-14.04',
  'ubuntu-16.04',
  'ubuntu-18.04'
]);
