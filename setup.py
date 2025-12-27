#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DevSecOps Gate - Setup Script
Automated Security Audit for CI/CD Pipeline
"""

from setuptools import setup, find_packages

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="devsecops-gate",
    version="1.0.0",
    author="DevSecOps Audit Team",
    author_email="audit@example.com",
    description="Automated Security Audit Gate for CI/CD Pipeline",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/devsecops-gate",
    packages=find_packages(include=["src", "src.*", "scripts", "dashboard"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    install_requires=[
        "bandit>=1.7.5",
        "safety>=2.3.5",
        "click>=8.1.7",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
        "jinja2>=3.1.2",
    ],
    extras_require={
        "dashboard": [
            "streamlit>=1.28.0",
            "plotly>=5.18.0",
            "pandas>=2.0.3",
        ],
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "devsecops-audit=scripts.run_audit:main",
            "devsecops-report=scripts.generate_report:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
