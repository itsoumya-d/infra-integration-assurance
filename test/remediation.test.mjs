import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateEnvironment } from '../src/evaluator.js';
import { generateRemediationRoadmap, buildDeliveryEvidence } from '../src/remediation.js';

describe('Remediation Roadmap and Evidence Delivery', () => {
  it('throws on invalid evaluation input', () => {
    assert.throws(() => generateRemediationRoadmap(null), /findings array required/);
    assert.throws(() => generateRemediationRoadmap({}), /findings array required/);
  });

  it('generates an empty roadmap for a fully compliant environment', () => {
    const perfectSnapshot = {
      environmentId: 'env-prod-100',
      backup: { configured: true, hoursSinceLastSuccess: 2, offsiteReplicated: true },
      hosts: [
        {
          hostname: 'srv-app-01',
          os: 'ubuntu-22.04',
          daysSinceLastPatch: 5,
          criticalCVEs: 0,
          endpointProtection: { installed: true, serviceRunning: true, definitionAgeHours: 4, tamperProtectionEnabled: true }
        }
      ],
      iam: { adminMFAEnforced: true, staleAccountCount: 0 },
      monitoring: { heartbeatActive: true, siemForwardingActive: true }
    };

    const evalRes = evaluateEnvironment(perfectSnapshot);
    const roadmap = generateRemediationRoadmap(evalRes);

    assert.equal(roadmap.totalActionCount, 0);
    assert.equal(roadmap.decommissioningCount, 0);
    assert.equal(roadmap.roadmap.phase1_immediate_24h.length, 0);
    assert.equal(roadmap.roadmap.phase2_standard_7d.length, 0);
    assert.equal(roadmap.roadmap.phase3_scheduled_30d.length, 0);

    const evidence = buildDeliveryEvidence(evalRes, roadmap);
    assert.ok(evidence.evidenceDigest.startsWith('sha256:'));
    assert.equal(evidence.complianceScore, 100);
    assert.equal(evidence.status, 'COMPLIANT');
    assert.equal(evidence.decommissioningRequired, false);
  });

  it('correctly stages prioritized phases and flags decommissioning for EOL systems', () => {
    const nonCompliantSnapshot = {
      environmentId: 'env-acquired-009',
      backup: { configured: true, hoursSinceLastSuccess: 48, offsiteReplicated: false },
      hosts: [
        {
          hostname: 'srv-win2008-01',
          os: 'windows-server-2008-r2', // EOL
          daysSinceLastPatch: 90,
          criticalCVEs: 3,
          endpointProtection: { installed: false, serviceRunning: false }
        },
        {
          hostname: 'srv-ubuntu-02',
          os: 'ubuntu-22.04',
          daysSinceLastPatch: 10,
          criticalCVEs: 0,
          endpointProtection: { installed: true, serviceRunning: true, definitionAgeHours: 5, tamperProtectionEnabled: false }
        }
      ],
      iam: { adminMFAEnforced: false, staleAccountCount: 4 },
      monitoring: { heartbeatActive: true, siemForwardingActive: false }
    };

    const evalRes = evaluateEnvironment(nonCompliantSnapshot);
    const roadmap = generateRemediationRoadmap(evalRes);

    assert.ok(roadmap.totalActionCount > 0);
    assert.ok(roadmap.decommissioningCount >= 1);
    assert.ok(roadmap.roadmap.decommissioning.some(d => d.target.includes('srv-win2008-01')));

    // Phase 1 should contain critical issues (Missing EDR, Critical CVEs, MFA)
    assert.ok(roadmap.roadmap.phase1_immediate_24h.length >= 2);
    assert.ok(roadmap.roadmap.phase1_immediate_24h.every(t => t.severity === 'CRITICAL'));

    // Phase 2 should contain high issues (Overdue backups, SIEM forwarding)
    assert.ok(roadmap.roadmap.phase2_standard_7d.length >= 1);
    assert.ok(roadmap.roadmap.phase2_standard_7d.every(t => t.severity === 'HIGH'));

    // Phase 3 should contain medium issues (Tamper protection, stale accounts)
    assert.ok(roadmap.roadmap.phase3_scheduled_30d.length >= 1);
    assert.ok(roadmap.roadmap.phase3_scheduled_30d.every(t => t.severity === 'MEDIUM'));

    // Evidence payload verification
    const evidence = buildDeliveryEvidence(evalRes, roadmap);
    assert.ok(evidence.evidenceDigest.startsWith('sha256:'));
    assert.equal(evidence.status, 'NON_COMPLIANT');
    assert.equal(evidence.decommissioningRequired, true);
    assert.ok(evidence.pendingActionCount >= 5);
  });
});
