# PortaSecura

![PortaSecura Logo](logo.png)

[![License: MIT with restrictions](https://img.shields.io/badge/License-MIT%20with%20restrictions-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-enabled-blue.svg)](https://www.docker.com/)
[![Solana](https://img.shields.io/badge/blockchain-solana-purple.svg)](https://solana.com)
[![Website](https://img.shields.io/website?up_message=online&url=https%3A%2F%2Fportasecura.io)](https://portasecura.io)
[![PyPI Version](https://img.shields.io/pypi/v/porta-secura)](https://pypi.org/project/porta-secura/)

PortaSecura is an enterprise-grade security solution that filters and manages AI agent outputs safely. Through a payment system utilizing PORTA tokens based on Solana blockchain, we provide secure and transparent services.

## Key Features

### 🛡️ Advanced Security Filtering
- Personal Information Detection and Filtering
- Credentials and API Key Protection
- Adult Content Filtering
- Financial Data Protection
- Custom Filter Support

### 🔄 Reverse Proxy System
- Secure Mediation between AI Agent Server and Client
- Real-time Content Inspection
- Traffic Optimization
- Load Balancing and Failover

### 💎 Blockchain Integration
- PORTA Token Payments on Solana
- Transparent Usage Metering
- Smart Contract Automation
- Decentralized Authentication

### 🔍 Monitoring and Analytics
- Real-time Usage Monitoring
- Detailed Filtering Analytics
- Performance Metrics
- Security Event Tracking

## Getting Started

### Prerequisites
```
- Python 3.8+
- Docker & Docker Compose
- Solana CLI (optional)
- Redis
```

## Installation

### Option 1: PyPI Installation (Recommended)

The easiest way to install PortaSecura is through pip:

```bash
pip install porta-secura
```

For development version:
```bash
pip install --pre porta-secura
```

With optional dependencies:
```bash
# For all features
pip install porta-secura[all]

# For blockchain features only
pip install porta-secura[blockchain]

# For proxy features only
pip install porta-secura[proxy]
```

### Option 2: Docker Installation

For containerized deployment:

1. Clone the repository
```bash
git clone https://github.com/portasecura/porta-secura.git
cd porta-secura
```

2. Configure environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Run with Docker
```bash
docker-compose up -d
```

### Option 3: Source Installation

For development or customization:

```bash
git clone https://github.com/portasecura/porta-secura.git
cd porta-secura
pip install -e .
```

## Quick Start

```python
# Simple usage
from porta_secura import FilterManager

# Initialize the filter manager
filter_manager = FilterManager()

# Filter content
filtered_content = filter_manager.process_response(
    content="Text containing sensitive information",
    sensitivity=0.7
)

# Advanced usage with blockchain integration
from porta_secura.blockchain import PaymentProcessor
from porta_secura.core import SecurityManager

# Initialize components
payment_processor = PaymentProcessor()
security_manager = SecurityManager()

# Configure wallet
wallet_address = "your-solana-wallet-address"

# Process secured content with payment
async def process_secure_content():
    # Verify wallet balance
    if await payment_processor.check_subscription_status(wallet_address):
        # Process content
        result = filter_manager.process_response(
            content="Sensitive content to filter",
            sensitivity=0.8
        )
        # Process payment
        await payment_processor.process_payment(wallet_address, 0.01)
        return result
    return None
```

## Package Structure

```
porta-secura/
├── core/
│   ├── filters.py       # Content filtering
│   ├── security.py      # Security features
│   └── proxy.py         # Reverse proxy
├── blockchain/
│   ├── solana.py        # Solana integration
│   └── wallet.py        # Wallet management
└── utils/
    ├── logging.py       # Logging utilities
    └── validation.py    # Input validation
```

## Dependencies

Core dependencies:
```
fastapi>=0.68.0
uvicorn>=0.15.0
pydantic>=1.8.2
aiohttp>=3.8.1
```

Optional dependencies:
```
# Blockchain features
solana>=0.23.0
spl-token>=0.2.0

# AI features
spacy>=3.2.0
transformers>=4.19.0
```


### Basic Usage

```python
from porta_secura import FilterManager

# Initialize the filter manager
filter_manager = FilterManager()

# Filter content
filtered_content = filter_manager.process_response(
    content="Text containing sensitive information",
    sensitivity=0.7
)
```

## Architecture

```mermaid
graph TD
    A[AI Agent Server] --> B[PortaSecura Proxy]
    B --> C[Content Filter]
    C --> D[Security Layer]
    D --> E[Blockchain Integration]
    E --> F[AI Agent Client]
```

## Security Features

PortaSecura includes robust security measures:
- JWT Authentication
- API Key Management
- Rate Limiting
- Input Validation
- CORS Support
- Encrypted Data Storage
- Audit Logging
- DDoS Protection

## Enterprise Features

### High Availability
- Load Balancing
- Automatic Failover
- Horizontal Scaling
- Disaster Recovery

### Monitoring
- Real-time Metrics
- Custom Alerting
- Performance Analytics
- Security Dashboards

### Compliance
- GDPR Compliance
- HIPAA Readiness
- SOC 2 Preparation
- Data Encryption

## Business Model

### Pricing Tiers
- **Basic**: 100k requests/month, $499/month
  - Basic filtering
  - Standard support
  - Single domain

- **Professional**: 1M requests/month, $1,999/month
  - Advanced filtering
  - Priority support
  - Multi-domain support
  - Custom filters

- **Enterprise**: Custom volume, Contact for pricing
  - Dedicated support
  - Custom integration
  - SLA guarantees
  - On-premise option

### PORTA Token Utility
- Service Payment
- Custom Filter Marketplace
- Governance Voting
- Staking Rewards


## Development

### Testing
Run the test suite:
```bash
python -m pytest tests/
```

### Contributing
We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Code Quality
- Linting: `pre-commit run --all-files`
- Type checking: `mypy porta_secura`
- Security scan: `bandit -r porta_secura`

## Support

### Enterprise Support
- 24/7 Technical Support
- Dedicated Account Manager
- Custom Feature Development
- Training and Onboarding

### Community Support
- Documentation: [https://docs.portasecura.io](https://docs.portasecura.io)
- Email: support@portasecura.io
- Discord: [PortaSecura Community](https://discord.gg/portasecura)
- GitHub Issues: Bug reports and feature requests

## Investor Information
- [Investor Deck](docs/business/pitch_deck.pdf)
- [Market Analysis](docs/business/market_analysis.md)
- [Roadmap](docs/business/roadmap.md)
- [Financial Projections](docs/business/financials.md)

## License
This project is licensed under the MIT License with restrictions - see the [LICENSE](LICENSE) file for details.

## Roadmap Highlights
- Q2 2025: Enterprise Features Release
- Q3 2025: Custom Filter Marketplace
- Q4 2025: On-premise Solution
- Q1 2026: Advanced Analytics Platform

---
Built with security in mind by the PortaSecura Team.

For business inquiries: business@portasecura.io  
For partnerships: partnerships@portasecura.io