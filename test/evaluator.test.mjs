import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateEnvironment } from '../src/evaluator.js';

describe('Environment Compliance Evaluator', () => {
  it('throws on invalid or null snapshot', () => {
    assert.throws(() => evaluateEnvironment(null), /object required/);
    assert.throws(() => evaluateEnvironment('invalid'), /object required/);
  });

  it('evaluates a fully compliant baseline environment as COMPLIANT with 100% score', () => {
    const perfectSnapshot = {
      environmentId: 'env-prod-001',
      backup: {
        configured: true,
        hoursSinceLastSuccess: 4,
        offsiteReplicated: true
      },
      hosts: [
        {
          hostname: 'srv-app-01',
          os: 'ubuntu-22.04',
          daysSinceLastPatch: 7,
          criticalCVEs: 0,
          endpointProtection: {
            installed: true,
            serviceRunning: true,
            definitionAgeHours: 6,
            tamperProtectionEnabled: true
          }
        },
        {
          hostname: 'srv-db-01',
          os: 'windows-server-2022',
          daysSinceLastPatch: 14,
          criticalCVEs: 0,
          endpointProtection: {
            installed: true,
            serviceRunning: true,
            definitionAgeHours: 12,
            tamperProtectionEnabled: true
          }
        }
      ],
      iam: {
        adminMFAEnforced: true,
        staleAccountCount: 0
      },
      monitoring: {
        heartbeatActive: true,
        siemForwardingActive: true
      }
    };

    const res = evaluateEnvironment(perfectSnapshot);
    assert.equal(res.complianceScore, 100);
    assert.equal(res.status, 'COMPLIANT');
    assert.equal(res.findingsCount, 0);
    assert.equal(res.criticalCount, 0);
    assert.equal(res.domainScores['CTRL-BCK-01'], 100);
    assert.equal(res.domainScores['CTRL-PTC-01'], 100);
    assert.equal(res.domainScores['CTRL-EDR-01'], 100);
    assert.equal(res.domainScores['CTRL-IAM-01'], 100);
    assert.equal(res.domainScores['CTRL-MON-01'], 100);
  });

  it('detects missing backups and unremediated critical CVEs as NON_COMPLIANT', () => {
    const degradedSnapshot = {
      environmentId: 'env-legacy-002',
      backup: {
        configured: false
      },
      hosts: [
        {
          hostname: 'srv-legacy-01',
          os: 'windows-server-2008-r2', // EOL OS
          daysSinceLastPatch: 120,
          criticalCVEs: 4,
          endpointProtection: {
            installed: false,
            serviceRunning: false
          }
        }
      ],
      iam: {
        adminMFAEnforced: false,
        staleAccountCount: 15
      },
      monitoring: {
        heartbeatActive: false,
        siemForwardingActive: false
      }
    };

    const res = evaluateEnvironment(degradedSnapshot);
    assert.ok(res.complianceScore < 50);
    assert.equal(res.status, 'NON_COMPLIANT');
    assert.ok(res.criticalCount >= 3);
    assert.ok(res.findings.some(f => f.title.includes('End-of-Life OS')));
    assert.ok(res.findings.some(f => f.title.includes('Backup Policy')));
    assert.ok(res.findings.some(f => f.title.includes('MFA Not Enforced')));
  });
});
