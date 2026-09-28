from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

API_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=API_ROOT / ".env", extra="ignore")

    database_url: str = f"sqlite:///{(API_ROOT / 'threatlens.db').as_posix()}"
    anthropic_api_key: str = ""
    llm_model: str = "claude-opus-5"
    brave_search_api_key: str = ""

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    abusech_auth_key: str = ""
    shodan_api_key: str = ""
    otx_api_key: str = ""
    urlscan_api_key: str = ""

    web_base_url: str = "http://localhost:3000"
    data_dir: Path = API_ROOT / "data"
    run_workers: int = 2
    fetch_timeout: float = 20.0


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    (s.data_dir / "articles").mkdir(exist_ok=True)
    (s.data_dir / "exports").mkdir(exist_ok=True)
    return s
