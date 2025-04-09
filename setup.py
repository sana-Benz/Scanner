from setuptools import setup, find_packages

setup(
    name="vuln_scanner",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "nmap3",
        "typer",
        "rich",
        "jinja2",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "vuln-scanner=vuln_scanner:main",
        ],
    },
) 