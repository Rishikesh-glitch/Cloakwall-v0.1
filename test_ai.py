import ollama
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI(title="LOCAL RESTAURANT MARKETING API")
messages = [{
    'role': 'system',
    'content': 'Tum ek professional food marketing expert ho. Tumhein hamesha sirf JSON format mein reply karna hai jisme compulsory yeh 3 keys honi chahiye: "ad_hook" (ek catchy headline), "insta_caption" (instagram post ke liye description), aur "hashtags" (kam se kam 3 trending hashtags ki ek list/array).'
}]

class PromptRequest(BaseModel):
    prompt:str
def is_prompt_safe(user_input:str):
    bad_words=["poison", "drugs", "free", "alcohol"]
    for word in bad_words:
        if word in user_input.lower():
            return False
    try:
        response=ollama.chat(
            model="llama-guard3:1b",
            messages=[{'role': 'user', 'content': user_input}]
        )
        guard_reply=response['message']['content']
        if "unsafe" in guard_reply.lower():
            return False
        return True
    except Exception as e:
        print()
        return False
@app.post("/compaign-generator")
async def compaign_generator(request:PromptRequest):
    if not is_prompt_safe:
        raise HTTPException(status_code=400, detail="Threat Detected Unsafe activity not allowed.")
    try:
        messages.append({'role':'user', 'content': user_input})
        response=ollama.chat(
            model="llama3.2",
            messages=messages,
            format='json',
            options={'temperature':0.0}
        )
        ai_reply =response['message']['content']
        ai_data= json.loads(ai_reply)

        print("==================================================")
        print("        🍗 SPATIAL FOOD MARKETING ENGINE 🍗        ")
        print("==================================================")
        print(f"🪝 AD HOOK      : {ai_data.get('ad_hook', 'N/A')}")
        print(f"📝 INSTA CAPTION: {ai_data.get('insta_caption', 'N/A')}")
        print(f"#️⃣ HASHTAGS     : {ai_data.get('hashtags', 'N/A')}")
        print("==================================================\n")

        messages.append({'role': 'assistant', 'content': ai_reply})
        return {
            "status": "success",
            "data": ai_data
        }
    except Exception as json_err:
            # Agar AI kabhi galti se galat JSON bhej de toh code crash nahi hoga
        raise HTTPException(status_code=500, detail=f"server Error: {str(json_err)}")

