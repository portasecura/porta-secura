from solana.rpc.api import Client
from solana.transaction import Transaction
from solana.system_program import TransferParams, transfer
from solana.keypair import Keypair
from spl.token.client import Token
from spl.token.constants import TOKEN_PROGRAM_ID
from typing import Optional, Dict
from decimal import Decimal

from porta_secura.config import settings


class SolanaManager:
    def __init__(self):
        self.client = Client(settings.SOLANA_NETWORK)
        self.porta_token = Token(
            self.client,
            settings.PORTA_TOKEN_ADDRESS,
            TOKEN_PROGRAM_ID,
            Keypair.generate()
        )

    async def check_balance(self, wallet_address: str) -> Decimal:
        try:
            balance = await self.porta_token.get_balance(wallet_address)
            return Decimal(balance['result']['value'])
        except Exception as e:
            raise ValueError(f"Failed to check balance: {str(e)}")

    async def verify_transaction(self, signature: str) -> Dict:
        try:
            transaction = await self.client.get_confirmed_transaction(signature)
            return {
                'status': transaction['result']['meta']['status'],
                'block_time': transaction['result']['blockTime'],
                'fee': transaction['result']['meta']['fee'],
                'amount': self._extract_amount(transaction)
            }
        except Exception as e:
            raise ValueError(f"Failed to verify transaction: {str(e)}")

    def _extract_amount(self, transaction: Dict) -> Decimal:
        try:
            for instruction in transaction['result']['transaction']['message']['instructions']:
                if instruction['programId'] == str(TOKEN_PROGRAM_ID):
                    return Decimal(instruction['data'])
        except Exception:
            return Decimal('0')


class PaymentProcessor:
    def __init__(self):
        self.solana_manager = SolanaManager()
        self.minimum_balance = settings.MINIMUM_BALANCE

    async def process_payment(self, wallet_address: str, amount: Decimal) -> bool:
        try:
            current_balance = await self.solana_manager.check_balance(wallet_address)
            if current_balance < amount:
                return False

            # Process the payment transaction
            transaction = Transaction()
            transfer_params = TransferParams(
                from_pubkey=wallet_address,
                to_pubkey=settings.PORTA_TOKEN_ADDRESS,
                lamports=int(amount * 1e9)  # Convert to lamports
            )
            transaction.add(transfer(transfer_params))

            # Sign and send transaction
            signature = await self.client.send_transaction(transaction)

            # Verify transaction success
            verification = await self.solana_manager.verify_transaction(signature)
            return verification['status'] == 'confirmed'

        except Exception as e:
            raise ValueError(f"Payment processing failed: {str(e)}")

    async def check_subscription_status(self, wallet_address: str) -> bool:
        try:
            balance = await self.solana_manager.check_balance(wallet_address)
            return balance >= self.minimum_balance
        except Exception as e:
            raise ValueError(f"Failed to check subscription status: {str(e)}")

    async def get_usage_metrics(self, wallet_address: str) -> Dict:
        try:
            transactions = await self.client.get_signatures_for_address(wallet_address)
            total_spent = Decimal('0')

            for tx in transactions['result']:
                verification = await self.solana_manager.verify_transaction(tx['signature'])
                if verification['status'] == 'confirmed':
                    total_spent += verification['amount']

            return {
                'total_transactions': len(transactions['result']),
                'total_spent': total_spent,
                'active_subscription': await self.check_subscription_status(wallet_address)
            }
        except Exception as e:
            raise ValueError(f"Failed to get usage metrics: {str(e)}")