# Keep the suite network-free: live NVD/KEV/EPSS enrichment is exercised with mocked HTTP in test_wp4.
import pytest

from app.config import get_settings


@pytest.fixture(autouse=True)
def _no_live_cve_enrichment(request, monkeypatch):
    if request.module.__name__.endswith("test_wp4"):
        return
    monkeypatch.setattr(get_settings(), "cve_enrichment", False)
