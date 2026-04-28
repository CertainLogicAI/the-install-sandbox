#!/usr/bin/env python3
"""Setup script for the-install-sandbox."""

from setuptools import setup, find_packages

setup(
    name="the-install-sandbox",
    version="0.1.0",
    description="Sandbox and scan ClawHub skills before installation",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="CertainLogic",
    author_email="dev@certainlogic.ai",
    url="https://github.com/CertainLogicAI/the-install-sandbox",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "typer>=0.12.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "test": ["pytest>=8.0"],
    },
    entry_points={
        "console_scripts": [
            "the_install_sandbox=the_install_sandbox.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    keywords="clawhub skill sandbox security scanner malware",
    license="MIT",
)
