# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name="porta-secura",
    version="1.0.1",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.68.0",
        "uvicorn>=0.15.0",
        "pydantic>=1.8.2",
        "aiohttp>=3.8.1",
        "python-jose>=3.3.0",
        "python-multipart>=0.0.5",
        "certifi>=2021.10.8",
        "redis>=4.2.0",
        "pyjwt>=2.3.0"
    ],
    extras_require={
        'blockchain': [
            "solana>=0.23.0",
            "spl-token>=0.2.0",
        ],
        'proxy': [
            "aiohttp>=3.8.1",
            "certifi>=2021.10.8",
        ],
        'ai': [
            "spacy>=3.2.0",
            "transformers>=4.19.0",
        ],
        'all': [
            "solana>=0.23.0",
            "spl-token>=0.2.0",
            "aiohttp>=3.8.1",
            "certifi>=2021.10.8",
            "spacy>=3.2.0",
            "transformers>=4.19.0",
        ]
    },
    python_requires=">=3.8",
    author="PortaSecura",
    author_email="contact@portasecura.io",
    description="A secure AI agent response filtering and proxy service using Solana blockchain",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/portasecura/porta-secura",
    project_urls={
        "Documentation": "https://docs.portasecura.io",
        "Source": "https://github.com/portasecura/porta-secura",
        "Tracker": "https://github.com/portasecura/porta-secura/issues",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Financial and Insurance Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Framework :: FastAPI",
    ]
)