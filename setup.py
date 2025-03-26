from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="wifi_scanner",
    version="1.0.0",
    author="Security Engineer",
    author_email="security@example.com",
    description="Ferramenta para escaneamento de redes Wi-Fi e brute force",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/z5ta9b5tbMC5Jr/wifi-scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "wifi-scanner=wifi_scanner:main",
        ],
    },
    include_package_data=True,
)