from pathlib import Path

from app.domain import Event
from app.engine import DetectionEngine
from app.profiles import ProfileStore
from app.reliability import ReliabilityDetector
from app.rules import RuleEngine


def _event(**overrides: object) -> Event:
    payload = {
        "event_id": "evt-1",
        "observed_at": "2026-08-25T00:00:00Z",
        "host_id": "host-1",
        "boot_id": "boot-1",
        "event_type": "PROCESS_EXEC",
        "subject": {"process_id": "boot:1:1", "executable": "/usr/sbin/nginx", "uid": 33},
        "object_type": "binary",
        "object_value": "/usr/sbin/nginx",
        "workload": {"workload_id": "nginx.service"},
        "result": "success",
        "attributes": {},
    }
    payload.update(overrides)
    return Event.from_dict(payload)


def _engine() -> DetectionEngine:
    root = Path(__file__).resolve().parents[3]
    return DetectionEngine(
        RuleEngine.from_directory(root / "policy" / "detection"),
        ProfileStore(minimum_observations=3),
    )


def test_temporary_execution_is_a_high_confidence_rule_match() -> None:
    assessment = _engine().assess(_event(subject={"process_id": "boot:1:1", "executable": "/tmp/payload", "uid": 33}, object_value="/tmp/payload"))
    assert assessment.security_score == 0.92
    assert assessment.baseline_updated is False
    assert assessment.findings[0].finding_id == "AG-RULE-001"
    assert assessment.counterfactual is not None
    assert "temporary storage" in assessment.counterfactual["verbalized_explanation"]


def test_baseline_requires_explicit_eligibility() -> None:
    engine = _engine()
    engine.assess(_event())
    profile = engine._profiles.profile_for("nginx.service")
    assert profile.observations == 0

    engine.assess(_event(attributes={"baseline_eligible": "true"}))
    assert profile.observations == 0

    engine.assess(
        _event(
            attributes={"baseline_eligible": "true"},
            trust={"host_attestation": "verified", "agent_integrity": "verified"},
        )
    )
    assert profile.observations == 1


def test_failed_attestation_freezes_learning_and_raises_critical_finding() -> None:
    assessment = _engine().assess(
        _event(
            attributes={"baseline_eligible": "true"},
            trust={"host_attestation": "failed", "agent_integrity": "verified"},
        )
    )
    assert assessment.telemetry_trust_score == 0.0
    assert assessment.baseline_updated is False
    assert assessment.findings[0].finding_id == "AG-TRUST-ATTESTATION-FAILED"


def test_markov_process_novelty_detects_unexpected_child_spawn() -> None:
    engine = _engine()
    # Train benign baseline (nginx -> worker)
    for _ in range(5):
        engine.assess(
            _event(
                attributes={"baseline_eligible": "true", "parent_executable": "/usr/sbin/nginx"},
                subject={"process_id": "boot:1:2", "executable": "/usr/sbin/nginx_worker", "uid": 33},
                object_value="/usr/sbin/nginx_worker",
                trust={"host_attestation": "verified", "agent_integrity": "verified"},
            )
        )

    # Malicious or novel transition: nginx -> /bin/sh
    attack_event = _event(
        attributes={"parent_executable": "/usr/sbin/nginx"},
        subject={"process_id": "boot:1:3", "executable": "/bin/sh", "uid": 33},
        object_value="/bin/sh",
    )
    assessment = engine.assess(attack_event)
    assert assessment.security_score >= 0.70
    assert any(f.finding_id == "AG-BEH-EXEC-NOVELTY" for f in assessment.findings)


def test_psi_resource_pressure_forecasting() -> None:
    engine = _engine()
    pressure_event = _event(
        event_type="RESOURCE_PRESSURE",
        object_type="cgroup",
        object_value="/sys/fs/cgroup/system.slice/nginx.service",
        attributes={"resource": "memory", "pressure_ratio": "0.75", "full_pressure_ratio": "0.40"},
    )
    assessment = engine.assess(pressure_event)
    assert assessment.reliability_score >= 0.80
    assert any(f.finding_id == "AG-REL-PRESSURE-FORECAST" for f in assessment.findings)
    assert assessment.findings[0].severity == "critical"
