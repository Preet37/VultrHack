import argparse
import asyncio
import base64
import os
import secrets
import shlex
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from uuid import uuid4

API_URL = "https://api.vultr.com/v2/instances"


class ReadySignals:
    def __init__(self):
        self._events = {}

    def register(self):
        token = secrets.token_urlsafe(32)
        self._events[token] = asyncio.Event()
        return token

    def signal(self, token):
        event = self._events.get(token)
        if event is None:
            return False
        event.set()
        return True

    async def wait(self, token, timeout=600):
        await asyncio.wait_for(self._events[token].wait(), timeout)

    def unregister(self, token):
        self._events.pop(token, None)


def docker_user_data(callback_url, ready_token):
    url = urlsplit(callback_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("Ready callback must be a public HTTPS URL without credentials or a query string")
    if not ready_token:
        raise ValueError("Ready token is required")
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        "export DEBIAN_FRONTEND=noninteractive\n"
        "apt-get update\n"
        "apt-get install -y docker.io curl\n"
        "systemctl enable --now docker\n"
        f"curl --fail --silent --show-error --retry 12 --retry-delay 5 --max-time 15 -X POST "
        f"-H {shlex.quote(f'Authorization: Bearer {ready_token}')} {shlex.quote(callback_url)}\n"
    )


class VultrInstances:
    def __init__(self, client, api_key):
        self.client = client
        self.headers = {"Authorization": f"Bearer {api_key}"}

    async def create(self, region, plan, os_id, callback_url, ready_token):
        script = docker_user_data(callback_url, ready_token)
        response = await self.client.post(
            API_URL,
            headers=self.headers,
            json={
                "region": region,
                "plan": plan,
                "os_id": os_id,
                "label": f"cerberus-{uuid4().hex[:12]}",
                "tags": ["cerberus"],
                "user_data": base64.b64encode(script.encode()).decode(),
            },
        )
        response.raise_for_status()
        return response.json()["instance"]["id"]

    async def wait_active(self, instance_id, timeout=600, interval=5):
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            response = await self.client.get(f"{API_URL}/{instance_id}", headers=self.headers)
            response.raise_for_status()
            instance = response.json()["instance"]
            if instance["status"] == "active" and instance["power_status"] == "running":
                return instance
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Instance {instance_id} did not become active")
            await asyncio.sleep(min(interval, remaining))

    async def destroy(self, instance_id, timeout=120, interval=5):
        url = f"{API_URL}/{instance_id}"
        response = await self.client.delete(url, headers=self.headers)
        response.raise_for_status()
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            response = await self.client.get(url, headers=self.headers)
            if response.status_code == 404:
                return
            response.raise_for_status()
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"Instance {instance_id} was not confirmed destroyed")
            await asyncio.sleep(min(interval, remaining))


@asynccontextmanager
async def temporary_instance(api, region, plan, os_id, callback_url, ready_token):
    instance_id = await api.create(region, plan, os_id, callback_url, ready_token)
    try:
        yield instance_id
    finally:
        await api.destroy(instance_id)


async def verify_instance(callback_url, host, port, region, plan, os_id):
    import httpx
    import uvicorn

    from connectivity import load_keys
    from main import callback_app, ready_signals

    docker_user_data(callback_url, "validation")
    api_key, _ = load_keys()
    region = region or os.getenv("VULTR_REGION", "ewr")
    plan = plan or os.getenv("VULTR_PLAN", "vc2-1c-1gb")
    token = ready_signals.register()
    server = uvicorn.Server(uvicorn.Config(callback_app, host=host, port=port, log_level="warning", access_log=False))
    server_task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if server_task.done():
                await server_task
                raise RuntimeError("Callback server did not start")
            await asyncio.sleep(0.1)
        async with httpx.AsyncClient(timeout=20) as client:
            api = VultrInstances(client, api_key)
            async with temporary_instance(api, region, plan, os_id, callback_url, token) as instance_id:
                print(f"Created instance {instance_id}")
                await api.wait_active(instance_id)
                print(f"Instance {instance_id} active; waiting for Docker readiness")
                await ready_signals.wait(token)
                print(f"Instance {instance_id} healthy; destroying it")
            print(f"Instance {instance_id} confirmed destroyed")
    finally:
        ready_signals.unregister(token)
        server.should_exit = True
        await server_task


def main():
    parser = argparse.ArgumentParser(description="Provision one temporary Vultr instance and verify Docker readiness")
    parser.add_argument("--callback-url", required=True, help="Public HTTPS URL forwarding to /internal/ready on this process")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--region")
    parser.add_argument("--plan")
    parser.add_argument("--os-id", type=int, default=2284)
    parser.add_argument("--execute", action="store_true", help="Authorize instance creation and subsequent destruction")
    args = parser.parse_args()
    if not args.execute:
        parser.error("Pass --execute to authorize creating and destroying one instance")
    asyncio.run(verify_instance(args.callback_url, args.host, args.port, args.region, args.plan, args.os_id))


if __name__ == "__main__":
    main()
