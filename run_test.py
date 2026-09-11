from fastapi import FastAPI
from fastapi.testclient import TestClient
from cloakwall.middleware import CloakwallGuardrailMiddleware

app = FastAPI()
app.add_middleware(CloakwallGuardrailMiddleware)

@app.post("/test")
async def test_endpoint(data: dict):
    return {"status": "ok", "received": data}

client = TestClient(app)

# Test 1: Normal Valid Request (Pass-through path)
res1 = client.post("/test", json={"tool": "search"})
print("Test 1 (Valid Payload):", res1.status_code, res1.json())
assert res1.status_code == 200

# Test 2: Invalid JSON (Fail-closed path)
res2 = client.post("/test", content="invalid_json_body", headers={"Content-Type": "application/json"})
print("Test 2 (Fail-Closed):", res2.status_code, res2.json())
assert res2.status_code == 400

print("\n✅ ALL TESTS PASSED!")