from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bsen",
    version="1.0.0",
    description="BSEN (Blue Security Endpoint Navigator): read-only cross-platform endpoint security auditor & digital forensics CLI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="b1l4l-sec",
    license="MIT",
    packages=find_packages(include=["bsen", "bsen.*"]),
    install_requires=[
        "psutil>=5.9.0",
        "rich>=13.7.0",
    ],
    extras_require={
        "remote": ["paramiko>=3.4.0", "pywinrm>=0.4.3"],
        "dev": ["pytest>=8.0.0", "black", "isort", "flake8", "mypy"],
    },
    entry_points={
        "console_scripts": [
            "bsen=bsen.cli:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
