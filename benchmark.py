import asyncio
import httpx

# Concurrency limit
SEMAPHORE = asyncio.Semaphore(10)

# Target payload
nested_payload = {
    "model": "gpt-3.5-turbo",
    "messages": [
        {"role": "user", "content": "Hello, this is a benchmark test"}
    ],
}


async def send_request(client, payload):
    async with SEMAPHORE:
        try:
            response = await client.post(
                "http://localhost:9000/v1/chat/completions",
                json=payload,
            )
            # Response status aur body yahan log karo
            print(f"Status: {response.status_code} | Body: {response.text}")
            return response.status_code
        except Exception as e:
            print(f"Request Error: {e}")
            return None


async def run_stress_test(total_requests):
    async with httpx.AsyncClient(timeout=60.0) as client:
        tasks = [
            send_request(client, nested_payload) for _ in range(total_requests)
        ]
        results = await asyncio.gather(*tasks)
        print(f"\nCompleted {len(results)} requests.")


if __name__ == "__main__":
    asyncio.run(run_stress_test(10))