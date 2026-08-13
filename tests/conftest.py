import os
import sys
from pathlib import Path

import pytest

# La API Key debe fijarse ANTES de importar app.py, porque app.py la lee
# de la variable de entorno una sola vez al cargarse el modulo.
TEST_API_KEY = "test-key-for-pytest-only"
os.environ.setdefault("PHISHPROTECT_API_KEY", TEST_API_KEY)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module  # noqa: E402


@pytest.fixture(scope="session")
def api_key():
    return os.environ["PHISHPROTECT_API_KEY"]


@pytest.fixture()
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


@pytest.fixture(scope="session")
def fixtures_dir():
    return Path(__file__).resolve().parent / "fixtures"
