from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import jwt
from decimal import Decimal

from porta_secura.core.filters import FilterManager
from porta_secura.blockchain.solana import PaymentProcessor
from porta_secura.config import settings

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION)
filter_manager = FilterManager()
payment_processor = PaymentProcessor()


class FilterRequest(BaseModel):
    content: str
    sensitivity: Optional[float] = Field(default=settings.DEFAULT_SENSITIVITY, ge=0, le=1)
    wallet_address: str


class FilterResponse(BaseModel):
    filtered_content: str
    sensitivity_score: float
    detection_summary: Dict[str, Any]


async def verify_token(authorization: str = Header(...)):
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication token")


@app.post("/api/v1/filter", response_model=FilterResponse)
async def filter_content(request: FilterRequest, token_payload: Dict = Depends(verify_token)):
    try:
        # Verify subscription status
        if not await payment_processor.check_subscription_status(request.wallet_address):
            raise HTTPException(status_code=402, detail="Invalid subscription")

        # Process the content through filters
        filtered_result = filter_manager.process_response(
            request.content,
            sensitivity=request.sensitivity
        )

        # Record usage metrics
        await payment_processor.process_payment(
            request.wallet_address,
            Decimal('0.01')  # Cost per request
        )

        return FilterResponse(
            filtered_content=filtered_result.filtered_text,
            sensitivity_score=filtered_result.sensitivity_score,
            detection_summary={
                "detected_items": filtered_result.detected_items,
                "modified": filtered_result.modified
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/verify-subscription")
async def verify_subscription(wallet_address: str, token_payload: Dict = Depends(verify_token)):
    try:

        status = await payment_processor.check_subscription_status(wallet_address)
        metrics = await payment_processor.get_usage_metrics(wallet_address)

        return {
            "active": status,
            "metrics": metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/custom-filter")
async def add_custom_filter(
        name: str,
        filter_code: str,
        wallet_address: str,
        token_payload: Dict = Depends(verify_token)
):
    try:
        if not await payment_processor.check_subscription_status(wallet_address):
            raise HTTPException(status_code=402, detail="Invalid subscription")

        # Compile and validate the custom filter
        try:
            filter_function = compile(filter_code, "<string>", "exec")
            namespace = {}
            exec(filter_function, namespace)
            filter_manager.add_custom_filter(name, namespace["filter_function"])
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid filter code: {str(e)}")

        return {"status": "success", "message": f"Custom filter '{name}' added successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/v1/custom-filter/{name}")
async def remove_custom_filter(
        name: str,
        wallet_address: str,
        token_payload: Dict = Depends(verify_token)
):
    try:
        if not await payment_processor.check_subscription_status(wallet_address):
            raise HTTPException(status_code=402, detail="Invalid subscription")

        filter_manager.remove_custom_filter(name)
        return {"status": "success", "message": f"Custom filter '{name}' removed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/usage")
async def get_usage(wallet_address: str, token_payload: Dict = Depends(verify_token)):
    try:
        metrics = await payment_processor.get_usage_metrics(wallet_address)
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)