from fastapi import FastAPI, Header, HTTPException
import re
import time
from pydantic import BaseModel

app = FastAPI()

class ChatRequest(BaseModel):
    prompt:str

def check_layer1(prompt:str):
    bad_words = ["hack", "ignore", "rules", "forget", "bypass"]
    for word in bad_words:
        if word.lower() in prompt.lower():
            return "Blocked"
    return "Safe"

def check_layer2(prompt:str):
    pattern = [r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)you\s+are\s+now\s+in\s+DAN\s+mode",
    r"(?i)system\s*:\s*override",
    r"(?i)reveal\s+your\s+system\s+prompt",
    r"(?i)sudo\s+mode"]
    for patt in pattern: 
        if re.search(patt, prompt):
            return "Blocked"
    return "Safe"

@app.post("/chat")
def run_guardrail(req:ChatRequest):
    start_time = time.perf_counter_ns

    l1_check = check_layer1(req.prompt)
    if l1_check == "Blocked":
        raise HTTPException(status_code=400, detail="Bad Word Found!")

    l2check = check_layer2(req.prompt)
    if l2check == "Blocked":
        raise HTTPException(status_code=400, detail="PII Leak")
    end_time = time.perf_counter_ns()
    latency = end_time - start_time/ 1_000_000
    return{
        "status":"Safe",
        "prompt":req.prompt,
        "latency": latency
        }