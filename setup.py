from setuptools import setup, find_packages

setup(
    name="vulnhuntr",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "rich>=13.7.1",
        "pydantic-xml>=2.11.0",
        "pydantic>=2.8.0",
        "anthropic>=0.30.1",
        "structlog>=24.2.0",
        "jedi==0.18.0",
        "parso==0.8.0",
        "openai>=1.51.2",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "vulnhuntr=vulnhuntr.__main__:run",
        ],
    },
    python_requires=">=3.10",
) 