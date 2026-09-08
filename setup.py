from setuptools import setup, find_packages

setup(
    name="wifiscanner",
    version="5.1.0",
    description="Research-grade passive Wi-Fi survey, client attribution, laboratory & IDS platform",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(include=["wifiscanner", "wifiscanner.*"]),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "full": ["scapy>=2.5.0", "rich>=14.1.0"],
        "research": ["scapy>=2.5.0", "rich>=14.1.0", "numpy", "matplotlib"],
    },
    entry_points={"console_scripts": ["wifiscanner=wifiscanner.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
        "Topic :: Education",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Development Status :: 5 - Production/Stable",
    ],
)
