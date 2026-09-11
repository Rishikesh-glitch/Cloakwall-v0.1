import asyncio
from nemoguardrails import RailsConfig, LLMRails

async def main():
    # 1. 'config' folder ka path dekar pure guardrail engine ko load kiya
    config = RailsConfig.from_path("./config")
    rails = LLMRails(config)

    print("⚡ NeMo Guardrails Engine Live! Type 'exit' to stop.\n")

    while True:
        user_message = input("User: ")
        if user_message.lower() == 'exit':
            break
        
        # 2. User ka message NeMo Engine ko bheja
        response = await rails.generate_async(messages=[{
            "role": "user",
            "content": user_message
        }])
        
        # 3. NeMo ka final filter kiya hua response print kiya
        print(f"Bot: {response['content']}\n")

if __name__ == "__main__":
    # Windows par asyncio loop smoothly chalane ke liye
    asyncio.run(main())
 