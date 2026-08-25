from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthcheck() -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


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
    # Query incidents
    inc_res = client.get("/v1/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.json()
    assert len(incidents) >= 1

    # Query provenance graph
    graph_res = client.get("/v1/graph")
    assert graph_res.status_code == 200
    graph = graph_res.json()
    assert graph["node_count"] >= 1
    assert len(graph["elements"]) >= 1


def test_assistant_chat_query() -> None:
    res = client.post("/v1/assistant/chat", json={"query": "Why was the last event flagged?"})
    assert res.status_code == 200
    reply = res.json()["reply"]
    assert "Explainability Report" in reply
    assert "demo.service" in reply or "unknown" in reply


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

    # Verify active actions
    active_res = client.get("/v1/actions/active")
    assert active_res.status_code == 200
    active = active_res.json()
    assert len(active) >= 1
