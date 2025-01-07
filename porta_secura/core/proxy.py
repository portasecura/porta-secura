import aiohttp
import asyncio
from typing import Dict, Optional, Any
from urllib.parse import urlparse
import ssl
import certifi
from porta_secura.core.filters import FilterManager
from porta_secura.blockchain.solana import PaymentProcessor


class ReverseProxy:
    def __init__(self):
        self.filter_manager = FilterManager()
        self.payment_processor = PaymentProcessor()
        self.session = None
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())

    async def initialize(self):
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def cleanup(self):
        if self.session:
            await self.session.close()

    async def forward_request(
            self,
            target_url: str,
            method: str,
            headers: Dict,
            data: Optional[Any] = None,
            wallet_address: Optional[str] = None,
            sensitivity: Optional[float] = None
    ) -> Dict:
        await self.initialize()

        # Verify subscription if wallet address is provided
        if wallet_address:
            subscription_active = await self.payment_processor.check_subscription_status(wallet_address)
            if not subscription_active:
                raise ValueError("Invalid subscription")

        # Forward the request
        try:
            async with self.session.request(
                    method,
                    target_url,
                    headers=self._prepare_headers(headers),
                    data=data,
                    ssl=self.ssl_context
            ) as response:
                response_data = await response.text()
                response_headers = dict(response.headers)

                # Filter the response if required
                if wallet_address:
                    filtered_response = self.filter_manager.process_response(
                        response_data,
                        sensitivity=sensitivity
                    )

                    # Process payment for the request
                    await self.payment_processor.process_payment(
                        wallet_address,
                        0.01  # Cost per request
                    )

                    return {
                        "status": response.status,
                        "headers": response_headers,
                        "data": filtered_response
                    }

                return {
                    "status": response.status,
                    "headers": response_headers,
                    "data": response_data
                }

        except Exception as e:
            raise ValueError(f"Proxy request failed: {str(e)}")

    def _prepare_headers(self, headers: Dict) -> Dict:
        # Remove hop-by-hop headers
        hop_by_hop_headers = {
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers',
            'transfer-encoding', 'upgrade'
        }

        return {
            k: v for k, v in headers.items()
            if k.lower() not in hop_by_hop_headers
        }


class ProxyManager:
    def __init__(self):
        self.proxy = ReverseProxy()
        self.target_hosts: Dict[str, str] = {}

    def add_target(self, name: str, url: str):
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid target URL")
        self.target_hosts[name] = url

    def remove_target(self, name: str):
        if name in self.target_hosts:
            del self.target_hosts[name]

    async def handle_request(
            self,
            target_name: str,
            method: str,
            headers: Dict,
            data: Optional[Any] = None,
            wallet_address: Optional[str] = None,
            sensitivity: Optional[float] = None
    ) -> Dict:
        if target_name not in self.target_hosts:
            raise ValueError(f"Unknown target: {target_name}")

        target_url = self.target_hosts[target_name]
        return await self.proxy.forward_request(
            target_url,
            method,
            headers,
            data,
            wallet_address,
            sensitivity
        )

    async def cleanup(self):
        await self.proxy.cleanup()