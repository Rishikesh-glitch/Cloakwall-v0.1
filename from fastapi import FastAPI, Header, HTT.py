from fastapi import FastAPI, Header, HTTPException
import re
from typing import Literal
from pydantic import BaseModel, Field
from fastapi import header
import time
app = FastAPI()

class CountGuardrail(BaseModel):
 prompt: str = Field(..., min_length=30)
@app.post("/word-count")
def word_count(prompt:CountGuardrail):
 clean = prompt.prompt.split()
 if len(clean) >50:
     return {"status":"bhai, limit 50 word ki h"}
 return {"staus":"request accepted!"}

class KeyGuardrail(BaseModel):
  prompt: str = Field(..., min_length=30)
@app.post("/api-key")
def my_function(x_api_key:str = Header(None)):
 if x_api_key != "Spatial_Secret_786":
     return 403, {"status": "Forbidden", "message": "bhai, api key glt h"}
 return {"processing..."}

class SemanticGuardrail(BaseModel):
    prompt: str = Field(..., min_length=30)
@app.post("/semantic-guardrail")
def semantic_guradrail(prompt:SemanticGuardrail):
  blacklist = ["stay in character", "ignore", "privious", "override", "bypass", "system"]
  for word in blacklist:
    if word in prompt.prompt.lower():
        return {"status": "blocked", "reason": "bad word detected!"}
  return {"status": "Success", "message": prompt.prompt} 

class OutputSanitization(BaseModel):
    AIGeneratedText: str = Field(..., min_length=30)
@app.post("/cleaning-layer")
def cleaning_layer(AIGeneratedText):
    blacklist = ["secret_key", "password", "abusive_word"]
    step = AIGeneratedText.AIGeneratedText
    for word in blacklist:
        if word in AIGeneratedText.AIGeneratedText.lower():
            step = re.sub(word, "[REDACTED]", AIGeneratedText)
        return {"status": "blocked", "message": step}
    return {"status": "Success", "message": step}

class InjectionGuardrail(BaseModel):
    prompt: str = Field(..., min_length=40)
@app.post("/find_guard")
def find_guard(prompt:InjectionGuardrail):
    target_symbols = [";", "--", "'"]
    target_keywords = ["DELETE", "TRUNCATE", "UNION", "SELECT"]
    for item in target_symbols + target_keywords.lower():
        if item in prompt.prompt.lower():
            raise HTTPException(status_code=403, detail="BHAI, database ke sath ched chad mat kro!")
        
    else:
         return {"status": "Success", "message": prompt.prompt}

class PromptInjection(BaseModel):
    AIResponse: str = Field(..., min_length=30)
@app.post("/Honey-Pot")
def honey_pot(AIResponse):
    secret_code = "REHAN_DEV_2026"
    if secret_code in AIResponse.AIResponse:
        raise HTTPException(status_code=403, detail= "security leak blocked!")
    else:
        return {"status":"Success", "message":AIResponse.AIResponse}

class RequestSizeGuardrail(BaseModel):
    prompt: str = Field(..., min_length=30)
@app.post("/size-guardrail")
def size_guardrail(prompt:RequestSizeGuardrail):
    if len(prompt.prompt) > 400:
        raise HTTPException(status_code=403, detail = "Bhai bohat bada h")
    else:
        return {"status":"Success", "message":prompt.prompt}

class PiiMasking(BaseModel):
    prompt: str = Field(..., min_length=30)
@app.post("/privacy-guard")
def privacy_guard(prompt:PiiMasking):
    pattern_p = r"\b\d{10}\b"
    pattern_e = r"[\w\.-]+@[\w\.-]+\.\w+"
    step1 = re.sub(pattern_p, "[PROTECTED]", prompt.prompt)
    step2 = re.sub(pattern_e, "[PROTECTED]", step1)
    return {"status": "protected", "message": step2}

class SlowInternetSimulator(BaseModel):
    prompt: str = Field(..., min_length=40)
@app.post("/rotating-knife")
def rotating_knife(prompt:SlowInternetSimulator):
    time.sleep(5)
    return {
        "status": "Success", 
        "message": "Ab internet chal gaya aur knife ghumna band!",
        "original_prompt": prompt.prompt
    }


class AISafetyPipeline(BaseModel):
    prompt: str = Field(..., min_length=10)
@app.post("/final-assembly")
def final_assembly(prompt:AISafetyPipeline):
    pattern_p = r"\b\d{10}\b"
    pattern_e = r"[\w\.-]+@[\w\.-]+\.\w+"
    blacklist = ["stay in character", "ignore", "privious", "override", "bypass", "system"]
    if len(prompt.prompt) > 400:
         raise HTTPException(status_code=400, detail="Bhai, message bahut bada hai!")
    for word in blacklist:
        if word in prompt.prompt.lower():
             raise HTTPException(status_code=403, detail="Bhai, system instructions ke sath ched-chad mat karo!")
    step1 = re.sub(pattern_p, "[PROTECTED]", prompt.prompt)
    step2 = re.sub(pattern_e, "[PROTECTED]", step1)
    return {"status": "cleaned", "final_output": step2}


REQUIRED_HISTORY = []
ERROR_LOGS = []
class ContetxAwareness(BaseModel):
    prompt: str = Field(..., min_length=10)
    version : float = 1.0

@app.post("/smart-guard")
def smart_guard(prompt:ContetxAwareness, x_api_key:str = Header(None)):
    t1 = time.time()
    clean = prompt.prompt.split()
    count = len(clean)
    bad_word = ["word1", "word2"]
    fake_role = ["admin", "root", "superuser"]
    danger_words = ["system prompt", "initial instructions", "base prompt"]
    current_text = prompt.prompt
    if x_api_key != "rehan2026":
        ERROR_LOGS.append({"error": "wrong api key", "prompt": prompt.prompt})
        raise HTTPException(status_code=401, detail="unotharized")
    if not prompt.prompt.isascii():
        ERROR_LOGS.append({"error": "Word in another language", "prompt": prompt.prompt})
        raise HTTPException(status_code=400, detail="please write in english")
    if count < 3:
        ERROR_LOGS.append({"error": "less Word", "prompt": prompt.prompt})
       raise HTTPException(status_code=400, detail=f"bhai, apne sirf {count} words likhe h")
    if "http" in prompt.prompt.lower():
        ERROR_LOGS.append({"error": "Bad req", "prompt": prompt.prompt})
        raise HTTPException(status_code=400, detail="bad request")
    if prompt.prompt.isupper():
        ERROR_LOGS.append({"error": "Word in uppercase", "prompt": prompt.prompt})
        raise HTTPException(status_code=400, detail="word in uppercase")
    if len(re.findall(r'\d', prompt.prompt)) > 5:
        ERROR_LOGS.append({"error": "too many numbers", "prompt": prompt.prompt})
        raise HTTPException(status_code=400, detail="too many numbers")
    if not prompt.prompt.endswith("?"):
        ERROR_LOGS.append({"error": "question nhi h", "prompt": prompt.prompt})
        raise HTTPException(status_code=400, detail="question  puch na")
    for word in fake_role:
        if word in prompt.prompt.lower():
            ERROR_LOGS.append({"error": "fake role use kr rha h", "prompt": prompt.prompt})
            raise HTTPException(status_code=401, detail= "pagal bana rha h")
    for word in bad_word:
       user_text = re.sub(word, "****", current_text, flags=re.IGNORECASE)
    if re.search(r'(.)\1{3,}', prompt.prompt):
        ERROR_LOGS.append({"error": "repeated Word", "prompt": prompt.prompt})
        raise HTTPException(status_code=400, detail="repeated word found!")
    for word in danger_words:
        if word in prompt.prompt.lower():
            raise HTTPException(status_code=403, detail="ye kya h bhai")
    pattern_p = r"\b\d{10}\b"
    pattern_e = r"[\w\.-]+@[\w\.-]+\.\w+"
    pattern_s = r"\d[-. ]?\d[-. ]?\d[-. ]?\d[-. ]?\d[-. ]?\d[-. ]?\d[-. ]?\d[-. ]?\d[-. ]?\d"
    step = re.sub(pattern_s, "[SECURE]", prompt.prompt)
    step = re.sub(pattern_p, "[PHONE_MASKED]", step)
    step = re.sub(pattern_e, "[EMAIL_MASKED]", step) 
    final_step = re.sub(r'[aeiouAEIOU]', "", step)
    t2 = time.time()
    total_time = t2 - t1
    record = {
        "prompt": prompt.prompt, 
        "time": f"{total_time:.4f}s",
        "version": prompt.version
    }
    key = "SPATIAL_2026_ADMIN"
    if key in prompt.prompt.lower():
        reverse = key[::-1]
        step = step.replace(key, reverse)
    if len(prompt.prompt) > 100:
        raise HTTPException(status_code=401, detail="too big")

    return {"status" : "clean & protected", "time": f"{total_time:.4f}s", 
            "message": step
    }






@app.get("/welcome/{user_name}")
def welcome_user(user_name:str):
    return {
         "message": f"hello {user_name}, welcome to Spatia app studio"
          "status": success
        }
@app.get("/stats")
def stats_average():
    if not REQUIRED_HISTORY:
        return {"message": "abhi tak koi data nhi hai"}
        total_time = sum(float(entry["time"].replace("s", "")) for entry in REQUEST_HISTORY)
        total_count = len(REQUEST_HISTORY)
        average = total_time/total_count
        return {
            "status": "safe", "average_time": f{"average:.2f}
        }
        
class SlowInternetSimulator(BaseModel):
    prompt: str = Field(..., min_length=40)
@app.post("/rotating-knife")
def rotating_knife(prompt:SlowInternetSimulator):
    time.sleep(5)
    return {
        "status": "Success", 
        "message": "Ab internet chal gaya aur knife ghumna band!",
        "original_prompt": prompt.prompt
    }

