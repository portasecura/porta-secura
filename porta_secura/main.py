import uvicorn
from fastapi import FastAPI
from porta_secura.api.routes import app
from porta_secura.core.proxy import ProxyManager
from porta_secura.config import settings
import asyncio
import signal
import sys

proxy_manager = ProxyManager()


async def shutdown_event():
    await proxy_manager.cleanup()


app.add_event_handler("shutdown", shutdown_event)


def signal_handler(sig, frame):
    print("Shutting down gracefully...")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(shutdown_event())
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    proxy_manager.add_target("default", "http://localhost:8001")

    uvicorn.run(
        app,
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=settings.API_WORKERS
    )


if __name__ == "__main__":
    main()