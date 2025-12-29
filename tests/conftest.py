"""
Pytest configuration and shared fixtures for Shellock tests.

This module configures Hypothesis profiles and provides shared test fixtures.
"""

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from hypothesis import Verbosity, settings

# Register Hypothesis profiles
settings.register_profile(
    "dev",
    max_examples=20,
    deadline=2000,
    verbosity=Verbosity.normal,
)

settings.register_profile(
    "ci",
    max_examples=100,
    deadline=5000,
    verbosity=Verbosity.normal,
)

settings.register_profile(
    "security",
    max_examples=1000,
    deadline=30000,
    verbosity=Verbosity.verbose,
)

# Load profile from environment variable or default to "dev"
profile_name = os.getenv("HYPOTHESIS_PROFILE", "dev")
settings.load_profile(profile_name)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_plaintext() -> bytes:
    """Sample plaintext data for encryption tests."""
    return b"SECRET_KEY=abc123\nDB_PASSWORD=hunter2\nAPI_TOKEN=xyz789"


@pytest.fixture
def sample_passphrase() -> str:
    """Sample passphrase for encryption tests."""
    return "test-passphrase-12345"


@pytest.fixture
def sample_env_file(temp_dir: Path) -> Path:
    """Create a sample .env file for testing."""
    env_file = temp_dir / "test.env"
    env_file.write_text(
        "# Test environment file\n"
        "SECRET_KEY=abc123\n"
        "DB_PASSWORD=hunter2\n"
        "API_TOKEN=xyz789\n"
    )
    return env_file
