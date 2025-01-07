import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
import os
import sys
from logging.handlers import RotatingFileHandler
import uuid


class CustomLogger:
    def __init__(self, name: str, log_dir: str = "logs"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)

        # Create logs directory if it doesn't exist
        Path(log_dir).mkdir(exist_ok=True)

        # Add rotating file handler
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, f"{name}.log"),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.INFO)

        # Add console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)

        # Create formatters and add them to the handlers
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )

        file_handler.setFormatter(file_formatter)
        console_handler.setFormatter(console_formatter)

        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _format_log_data(self, data: Dict[str, Any]) -> str:
        """Format dictionary data as JSON string."""
        return json.dumps(data, default=str)

    def log_request(
            self,
            request_id: str,
            wallet_address: str,
            endpoint: str,
            method: str,
            data: Optional[Dict[str, Any]] = None
    ):
        """Log incoming API request."""
        log_data = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "wallet_address": wallet_address,
            "endpoint": endpoint,
            "method": method,
            "data": data
        }
        self.logger.info(f"Incoming request: {self._format_log_data(log_data)}")

    def log_response(
            self,
            request_id: str,
            status_code: int,
            response_time: float,
            data: Optional[Dict[str, Any]] = None
    ):
        """Log API response."""
        log_data = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "status_code": status_code,
            "response_time_ms": response_time,
            "data": data
        }
        self.logger.info(f"Response sent: {self._format_log_data(log_data)}")

    def log_filter_result(
            self,
            request_id: str,
            wallet_address: str,
            sensitivity: float,
            detected_items: int,
            modifications_made: bool
    ):
        """Log content filter results."""
        log_data = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "wallet_address": wallet_address,
            "sensitivity": sensitivity,
            "detected_items": detected_items,
            "modifications_made": modifications_made
        }
        self.logger.info(f"Filter result: {self._format_log_data(log_data)}")

    def log_error(
            self,
            request_id: str,
            error_type: str,
            error_message: str,
            stack_trace: Optional[str] = None
    ):
        """Log error information."""
        log_data = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "error_type": error_type,
            "error_message": error_message,
            "stack_trace": stack_trace
        }
        self.logger.error(f"Error occurred: {self._format_log_data(log_data)}")

    def log_blockchain_transaction(
            self,
            request_id: str,
            wallet_address: str,
            transaction_type: str,
            amount: float,
            status: str
    ):
        """Log blockchain transaction details."""
        log_data = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "wallet_address": wallet_address,
            "transaction_type": transaction_type,
            "amount": amount,
            "status": status
        }
        self.logger.info(f"Blockchain transaction: {self._format_log_data(log_data)}")

    def log_security_event(
            self,
            request_id: str,
            event_type: str,
            wallet_address: str,
            details: Dict[str, Any]
    ):
        """Log security-related events."""
        log_data = {
            "request_id": request_id,"timestamp": datetime.utcnow(),
            "event_type": event_type,
            "wallet_address": wallet_address,
            "details": details
        }
        self.logger.warning(f"Security event: {self._format_log_data(log_data)}")

    def log_metrics(
        self,
        request_id: str,
        metric_type: str,
        wallet_address: str,
        values: Dict[str, Any]
    ):
        """Log performance and usage metrics."""
        log_data = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "metric_type": metric_type,
            "wallet_address": wallet_address,
            "values": values
        }
        self.logger.info(f"Metrics: {self._format_log_data(log_data)}")

    def log_proxy_event(
        self,
        request_id: str,
        source_url: str,
        target_url: str,
        status_code: int,
        response_time: float
    ):
        """Log reverse proxy events."""
        log_data = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "source_url": source_url,
            "target_url": target_url,
            "status_code": status_code,
            "response_time_ms": response_time
        }
        self.logger.info(f"Proxy event: {self._format_log_data(log_data)}")

class MetricsCollector:
    def __init__(self, logger: CustomLogger):
        self.logger = logger
        self.metrics = {}

    def record_request_metric(
        self,
        wallet_address: str,
        endpoint: str,
        response_time: float,
        status_code: int
    ):
        """Record API request metrics."""
        if wallet_address not in self.metrics:
            self.metrics[wallet_address] = {
                "total_requests": 0,
                "total_response_time": 0,
                "status_codes": {},
                "endpoints": {}
            }

        metrics = self.metrics[wallet_address]
        metrics["total_requests"] += 1
        metrics["total_response_time"] += response_time

        # Record status code
        metrics["status_codes"][status_code] = metrics["status_codes"].get(status_code, 0) + 1

        # Record endpoint usage
        if endpoint not in metrics["endpoints"]:
            metrics["endpoints"][endpoint] = {
                "count": 0,
                "total_response_time": 0
            }
        metrics["endpoints"][endpoint]["count"] += 1
        metrics["endpoints"][endpoint]["total_response_time"] += response_time

        # Log metrics
        self.logger.log_metrics(
            request_id=str(uuid.uuid4()),
            metric_type="request",
            wallet_address=wallet_address,
            values={
                "endpoint": endpoint,
                "response_time": response_time,
                "status_code": status_code
            }
        )

    def record_filter_metric(
        self,
        wallet_address: str,
        sensitivity: float,
        detected_items: int,
        processing_time: float
    ):
        """Record content filter metrics."""
        if wallet_address not in self.metrics:
            self.metrics[wallet_address] = {}

        metrics = self.metrics[wallet_address]

        if "filter_metrics" not in metrics:
            metrics["filter_metrics"] = {
                "total_filtered": 0,
                "total_detected_items": 0,
                "total_processing_time": 0,
                "sensitivity_levels": {}
            }

        filter_metrics = metrics["filter_metrics"]
        filter_metrics["total_filtered"] += 1
        filter_metrics["total_detected_items"] += detected_items
        filter_metrics["total_processing_time"] += processing_time

        # Record sensitivity level usage
        sensitivity_key = str(round(sensitivity, 2))
        if sensitivity_key not in filter_metrics["sensitivity_levels"]:
            filter_metrics["sensitivity_levels"][sensitivity_key] = 0
        filter_metrics["sensitivity_levels"][sensitivity_key] += 1

        # Log metrics
        self.logger.log_metrics(
            request_id=str(uuid.uuid4()),
            metric_type="filter",
            wallet_address=wallet_address,
            values={
                "sensitivity": sensitivity,
                "detected_items": detected_items,
                "processing_time": processing_time
            }
        )

    def get_wallet_metrics(self, wallet_address: str) -> Dict[str, Any]:
        """Get aggregated metrics for a specific wallet."""
        if wallet_address not in self.metrics:
            return {}

        metrics = self.metrics[wallet_address]

        # Calculate averages and other derived metrics
        total_requests = metrics.get("total_requests", 0)
        if total_requests > 0:
            avg_response_time = metrics["total_response_time"] / total_requests
        else:
            avg_response_time = 0

        return {
            "total_requests": total_requests,
            "average_response_time": avg_response_time,
            "status_code_distribution": metrics.get("status_codes", {}),
            "endpoint_usage": metrics.get("endpoints", {}),
            "filter_metrics": metrics.get("filter_metrics", {})
        }

    def clear_metrics(self, wallet_address: str = None):
        """Clear metrics for a specific wallet or all wallets."""
        if wallet_address:
            if wallet_address in self.metrics:
                del self.metrics[wallet_address]
        else:
            self.metrics.clear()