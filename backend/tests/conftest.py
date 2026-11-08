from pathlib import Path
import pytest
from app.evidence_store import evidence_store


@pytest.fixture(scope="session", autouse=True)
def isolate_test_database():
    """
    Ensures automated pytest runs write to `baitbox_test.db` instead of the
    live user-facing `baitbox.db` history database.
    """
    original_db_path = evidence_store.db_path
    test_db_path = original_db_path.parent / "baitbox_test.db"
    evidence_store.db_path = test_db_path
    evidence_store._init_db()
    yield
    evidence_store.db_path = original_db_path
    try:
        if test_db_path.exists():
            test_db_path.unlink()
    except Exception:
        pass
