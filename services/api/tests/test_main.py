from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.assistant import GroundingValidator
from app.main import app

client = TestClient(app)


def test_healthcheck() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["team"] == "Team_Red_Eagle"


def test_tmp_execution_is_assessed_as_high_risk() -> None:
    response = client.post(
        "/v1/events/assess",
        json={
            "observed_at": datetime.now(UTC).isoformat(),
            "host_id": "demo-host",
            "boot_id": "boot-1",
            "event_type": "PROCESS_EXEC",
            "subject": {
                "process_id": "boot-1:10:100",
                "pid": 10,
                "ppid": 1,
                "executable": "/tmp/unknown",
                "uid": 1000,
            },
            "object_type": "binary",
            "object_value": "/tmp/unknown",
            "workload": {"workload_id": "demo.service"},
            "result": "success",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["security_score"] == 0.92
    assert data["counterfactual"] is not None
    assert "temporary storage" in data["counterfactual"]["verbalized_explanation"]


def test_graph_and_incident_retrieval() -> None:
    inc_res = client.get("/v1/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.json()
    assert len(incidents) >= 1

    graph_res = client.get("/v1/graph")
    assert graph_res.status_code == 200
    graph = graph_res.json()
    assert graph["node_count"] >= 1
    assert len(graph["elements"]) >= 1


def test_mitre_navigator_layer_export() -> None:
    res = client.get("/v1/mitre/navigator")
    assert res.status_code == 200
    layer = res.json()
    assert layer["name"] == "वज्र (Vajra) Threat Detection Layer - Team Red Eagle"
    assert layer["domain"] == "enterprise-attack"
    assert len(layer["techniques"]) >= 1
    assert layer["gradient"]["minValue"] == 0.2


def test_telemetry_overhead_metrics() -> None:
    res = client.get("/v1/metrics/overhead")
    assert res.status_code == 200
    metrics = res.json()
    assert "cpu_overhead_percent" in metrics
    assert "memory_rss_mb" in metrics
    assert "event_processing_latency_ms" in metrics
    assert metrics["ring_buffer_drop_rate_percent"] == 0.00
    assert metrics["cpu_overhead_percent"] <= 5.0
    assert metrics["memory_rss_mb"] <= 50.0


def test_grounding_validator() -> None:
    allowed = {"/usr/sbin/nginx", "101", "/tmp/nc", "198.51.100.4"}
    valid_text = "Process PID 101 running /usr/sbin/nginx executed /tmp/nc connecting to 198.51.100.4."
    is_valid, _ = GroundingValidator.validate(valid_text, allowed)
    assert is_valid is True

    hallucinated_text = "Process PID 9999 executed /opt/secret_malware to drop /root/trojan on 1.2.3.4."
    is_valid, reason = GroundingValidator.validate(hallucinated_text, allowed)
    assert is_valid is False
    assert "Ungrounded entities" in reason


def test_assistant_chat_query() -> None:
    res = client.post("/v1/assistant/chat", json={"query": "Why was the last event flagged?"})
    assert res.status_code == 200
    reply = res.json()["reply"]
    assert "Explainability Report" in reply or "Vajra" in reply


def test_remediation_action_execution() -> None:
    res = client.post(
        "/v1/actions/execute",
        json={
            "action_type": "FREEZE_CGROUP",
            "target": "demo.service",
            "analyst_approved": True,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "Audit Receipt" in data["message"]
    assert data["receipt"]["action_type"] == "FREEZE_CGROUP"
