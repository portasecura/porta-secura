import re
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
import base64
from urllib.parse import urlparse


class DataValidator:
    @staticmethod
    def validate_wallet_address(address: str) -> bool:
        """Validate Solana wallet address format."""
        if not address:
            return False

        # Check if address is base58 encoded and correct length
        try:
            decoded = base58.b58decode(address)
            return len(decoded) == 32
        except:
            return False

    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """Validate API key format."""
        if not api_key:
            return False

        # API keys should be 64 character hex strings
        pattern = r'^[a-fA-F0-9]{64}$'
        return bool(re.match(pattern, api_key))

    @staticmethod
    def validate_sensitivity(sensitivity: float) -> bool:
        """Validate sensitivity value is between 0 and 1."""
        return isinstance(sensitivity, (int, float)) and 0 <= sensitivity <= 1

    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    @staticmethod
    def sanitize_input(data: Union[str, Dict, List]) -> Union[str, Dict, List]:
        """Sanitize input data to prevent injection attacks."""
        if isinstance(data, str):
            # Remove potential script tags and other dangerous content
            sanitized = re.sub(r'<script.*?>.*?</script>', '', data, flags=re.IGNORECASE | re.DOTALL)
            sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'on\w+=".*?"', '', sanitized, flags=re.IGNORECASE)
            return sanitized
        elif isinstance(data, dict):
            return {k: DataValidator.sanitize_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [DataValidator.sanitize_input(item) for item in data]
        return data

    @staticmethod
    def validate_custom_filter(filter_code: str) -> bool:
        """Validate custom filter code for security."""
        # List of forbidden keywords that could be dangerous
        forbidden = [
            'import os',
            'import sys',
            'import subprocess',
            '__import__',
            'eval(',
            'exec(',
            'open(',
            'file(',
            'system(',
            'popen('
        ]

        # Check for forbidden keywords
        for keyword in forbidden:
            if keyword in filter_code.lower():
                return False

        # Check for proper function definition
        if not re.search(r'def\s+filter_function\s*\([^)]*\)\s*:', filter_code):
            return False

        return True

    @staticmethod
    def validate_request_data(data: Dict[str, Any]) -> List[str]:
        """Validate request data and return list of validation errors."""
        errors = []

        required_fields = ['content', 'wallet_address']
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        if 'wallet_address' in data and not DataValidator.validate_wallet_address(data['wallet_address']):
            errors.append("Invalid wallet address format")

        if 'sensitivity' in data and not DataValidator.validate_sensitivity(data['sensitivity']):
            errors.append("Sensitivity must be between 0 and 1")

        if 'api_key' in data and not DataValidator.validate_api_key(data['api_key']):
            errors.append("Invalid API key format")

        return errors

    @staticmethod
    def validate_custom_filter_request(data: Dict[str, Any]) -> List[str]:
        """Validate custom filter request data."""
        errors = []

        if 'name' not in data:
            errors.append("Missing filter name")
        elif not isinstance(data['name'], str) or len(data['name']) > 50:
            errors.append("Invalid filter name")

        if 'filter_code' not in data:
            errors.append("Missing filter code")
        elif not DataValidator.validate_custom_filter(data['filter_code']):
            errors.append("Invalid or unsafe filter code")

        return errors