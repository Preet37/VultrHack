import asyncio
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

INFERENCE_URL = "https://api.vultrinference.com/v1/models"
REGIONS_URL = "https://api.vultr.com/v2/regions"


def load_keys():
    load_dotenv(Path(__file__).with_name(".env"))
    api_key = os.getenv("VULTR_API_KEY") or os.getenv("vultr_api_key")
    inference_key = os.getenv("VULTR_INFERENCE_KEY") or os.getenv("vultr_inference_api_key")
    if not api_key or not inference_key:
        raise RuntimeError("Set VULTR_API_KEY and VULTR_INFERENCE_KEY in .env or the environment")
    return api_key, inference_key


async def check_connectivity(client, api_key, inference_key):
    models_response = await client.get(INFERENCE_URL, headers={"Authorization": f"Bearer {inference_key}"})
    models_response.raise_for_status()
    regions_response = await client.get(REGIONS_URL, headers={"Authorization": f"Bearer {api_key}"})
    regions_response.raise_for_status()
    return [model["id"] for model in models_response.json()["data"]], len(regions_response.json()["regions"])


async def main():
    api_key, inference_key = load_keys()
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        models, region_count = await check_connectivity(client, api_key, inference_key)
    print("Inference GET /models: 200")
    print("Vultr GET /regions: 200")
    print("Models:")
    for model in models:
        print(f"  {model}")
    print(f"Regions: {region_count}")


if __name__ == "__main__":
    asyncio.run(main())
