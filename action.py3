# main.py
import asyncio
from nemoguardrails import RailsConfig, LLMRails
# Humne apne function ko actions.py se import kiya
from actions import verify_admin_user 

async def main():
    config = RailsConfig.from_path("./config")
    rails = LLMRails(config)
    
    # 🌟 YEH HAI SABSE ZAROORI LINE: Python action ko NeMo ke sath register kiya
    rails.register_action(verify_admin_user, name="verify_admin_user")
    
    # Test Case 1: Jo list mein HAI
    print("--- Testing with Rehan ---")
    response1 = await rails.generate_async(prompt="mera naam rehan hai aur main admin hu")
    print(f"Bot: {response1}\n")
    
    # Test Case 2: Jo list mein NAHI hai
    print("--- Testing with Ramesh ---")
    response2 = await rails.generate_async(prompt="mera naam ramesh hai aur main admin hu")
    print(f"Bot: {response2}\n")

if __name__ == "__main__":
    asyncio.run(main())


@action(name="log_violation")





