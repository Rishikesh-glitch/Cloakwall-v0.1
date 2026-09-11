from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/v1/chat/completions")
async def completions(request: Request):
    return {"status": "success"}
