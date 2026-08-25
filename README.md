# AegisGraph

An explainable Linux runtime-security and reliability platform. AegisGraph collects
kernel-level telemetry, learns workload-specific normal behaviour, reconstructs
provenance graphs, and produces policy-governed response recommendations.

## Repository layout

- `agent/` — privileged Linux sensor written in Rust.
- `bpf/` — CO-RE eBPF programs and shared kernel/user-space event definitions.
- `contracts/` — versioned event schemas shared across services.
- `services/` — ingestion, detection, graph, response, and API services.
- `policy/` — detection and response policies; policy is separate from ML output.
- `infra/` — local Docker environment and database initialization.
- `test-lab/` — safe demonstrations of attack and reliability scenarios.
- `docs/` — design records and operating documentation.

## Design principles

1. Kernel events are evidence, not raw conclusions.
2. Normality is learned per workload identity, not per host.
3. Rules, statistics, sequences, and graph anomalies are fused with calibrated risk.
4. Every alert must include evidence, normal-behaviour comparison, and a causal path.
5. ML and LLMs recommend; only signed policy can authorize containment.
6. Automatic responses are scoped, reversible, time-bound, and audited.

## Local development

1. Copy `.env.example` to `.env` and change all local credentials.
2. Start dependencies with `docker compose -f infra/docker-compose.yml up -d`.
3. Start the API with `uv run --directory services/api uvicorn app.main:app --reload --port 8000`.
4. Start the detector with `uv run --directory services/detector python -m app.worker`.

The eBPF agent requires a supported Linux kernel. Its source is intentionally kept
separate from the API so the platform can run in simulated-event mode during UI and
ML development on non-Linux workstations.
