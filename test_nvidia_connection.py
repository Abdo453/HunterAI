#!/usr/bin/env python3
"""
Test NVIDIA NIM API Connection
"""
import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

async def test_nvidia():
    api_key = os.getenv("NVIDIA_API_KEY")
    base_url = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
    model = os.getenv("HUNTER_AI_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")
    
    print(f"Testing NVIDIA NIM API...")
    print(f"Base URL: {base_url}")
    print(f"Model: {model}")
    print(f"API Key: {'SET' if api_key and api_key != 'YOUR_NVIDIA_API_KEY_HERE' else 'NOT SET'}")
    
    if not api_key or api_key == "YOUR_NVIDIA_API_KEY_HERE":
        print("\n❌ NVIDIA_API_KEY not set in .env")
        print("Please edit .env and add your NVIDIA API key")
        return False
    
    try:
        from openai import AsyncOpenAI
        client = AsyncOpenAI(api_key=api_key, base_url=base_url)
        
        print("\nSending test request...")
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a security expert."},
                {"role": "user", "content": "Say 'NVIDIA NIM connection successful' and nothing else."}
            ],
            max_tokens=50,
            temperature=0
        )
        
        content = response.choices[0].message.content
        print(f"\n✅ SUCCESS: NVIDIA NIM responded:")
        print(f"   {content}")
        return True
        
    except Exception as e:
        print(f"\n❌ FAILED: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_nvidia())
    exit(0 if result else 1)