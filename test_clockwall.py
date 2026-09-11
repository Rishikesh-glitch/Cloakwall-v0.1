# Agar file ka naam main.py hai:
from middleware import CloakwallGuardrailMiddleware
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from cloakwall_middleware import CloakwallGuardrailMiddleware  # your file name

app = FastAPI()
app.add_middleware(CloakwallGuardrailMiddleware)


@app.post("/execute")
async def execute_tool(data: dict):
    return {"status": "success", "executed_data": data}


client = TestClient(app)


def test_normal_payload_pass():
    # Matching preview and final args (No Drift)
    payload = {
        "tools": [
            {
                "name": "db_write",
                "type": "write",
                "preview_arguments": {"user_id": 10},
                "arguments": {"user_id": 10},
            }
        ]
    }
    response = client.post("/execute", json=payload)
    assert response.status_code == 200
    assert "X-Cloakwall-Latency-MS" in response.headers
    assert "X-Cloakwall-Receipt-ID" in response.headers


def test_argument_drift_blocked():
    # Drift detected: preview != final arguments
    payload = {
        "tools": [
            {
                "name": "sql_delete",
                "type": "write",
                "preview_arguments": {"table": "users", "id": 5},
                "arguments": {"table": "users", "id": 999},  # Tampered!
            }
        ]
    }
    response = client.post("/execute", json=payload)
    assert response.status_code == 403
    assert response.json()["error"] == "Cloakwall Security Gate Triggered"
    assert response.json()["audit_receipt"]["status"] == "BLOCKED"


def test_non_payload_pass():
    response = client.get("/execute")
    assert response.status_code == 405  # Method not allowed by route, passed gate