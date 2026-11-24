# infra-integration-assurance

Automated environment integration and compliance assurance engine for managed service providers and infrastructure teams.

Evaluates customer infrastructure snapshots against standardized baseline controls (backup, patching, EDR/XDR, IAM, monitoring, configuration compliance), calculates deterministic compliance metrics, flags legacy/unsupported systems for decommissioning, and emits verifiable service delivery audit evidence.

## Core Capabilities

- **Environment Baseline Assessment**: Validates infrastructure configurations against standardized MSP operational benchmarks.
- **Multi-Domain Control Coverage**:
  - `BACKUP_POLICY`: Backup schedule existence, successful execution <= 24h, offsite replication verification.
  - `PATCH_HYGIENE`: OS patch latency <= 30 days, zero unpatched critical CVEs.
  - `ENDPOINT_PROTECTION`: EDR/XDR agent health, definitions updated <= 48h, active tamper protection.
  - `IDENTITY_ACCESS`: MFA enforcement on administrative roles, zero standing root/global admins, automatic detection of stale accounts (> 90 days inactivity).
  - `MONITORING_TELEMETRY`: Continuous heartbeat telemetry and SIEM audit log forwarding.
- **Decommissioning Intelligence**: Identifies end-of-life OS releases and unmanaged legacy workloads that pose operational and security liability.
- **Verifiable Delivery Evidence**: Generates structured `evidence.json` reports with cryptographic checksums and executive compliance summaries.

## Getting Started

### Prerequisites

- Node.js >= 20.0.0

### Run Tests

```bash
npm test
```

## Architecture

```
src/
  ├── evaluator.js    # Core compliance rule engine and scoring logic
  ├── standards.js    # Baseline policy definitions and severity weights
  └── reporter.js     # Evidence formatting and roadmap generator
test/
  └── evaluator.test.mjs  # Unit and integration test suite
```

## License

MIT. Copyright (c) 2026 Soumya Debnath.
