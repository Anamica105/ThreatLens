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

    # CVE enrichment (NVD 2.0, CISA KEV, FIRST EPSS). Only CVE ids are ever sent.
    cve_enrichment: bool = True
    nvd_api_key: str = ""
    cve_cache_hours: int = 24
    enrichment_timeout: float = 10.0

    # Run budget per depth (spec section 12): wall-clock minutes and LLM tokens.
    run_budgets: dict = {
        "quick": {"max_minutes": 5, "max_tokens": 250_000},
        "standard": {"max_minutes": 10, "max_tokens": 600_000},
        "deep": {"max_minutes": 20, "max_tokens": 1_200_000},
    }
    budget_warn_pct: float = 80.0
    budget_enforce: bool = False  # true: stop the run at the next stage boundary once over budget

    # View audit (spec section 13): one row per user + entity per window.
    audit_dedupe_minutes: int = 10

    # Secrets at rest (spec section 13: OSINT keys in a vault). Fernet key for values stored in the `setting` table.
    # Env THREATLENS_SECRET_KEY; if empty, one is generated into <data_dir>/.secret_key (gitignored) with a warning.
    threatlens_secret_key: str = ""

    # Auth (spec section 12: SSO via OIDC).
    #   dev    - trust the `X-User` header sent by the web app's user switcher (falls back to the first user). Local only.
    #   header - trust only `auth_header` (an email set by an OIDC-validating reverse proxy such as oauth2-proxy),
    #            and only when the TCP peer is in `auth_trusted_proxies`. `X-User` is ignored.
    #   oidc   - native bearer-token validation; not implemented yet (501). Planned keys: oidc_issuer,
    #            oidc_audience, oidc_jwks_url (default <issuer>/.well-known/jwks.json), oidc_email_claim, oidc_role_claim.
    auth_mode: str = "dev"
    auth_header: str = "X-Forwarded-Email"
    auth_trusted_proxies: str = "127.0.0.1,::1"  # comma-separated IPs or CIDRs
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    oidc_email_claim: str = "email"
    oidc_role_claim: str = "roles"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    (s.data_dir / "articles").mkdir(exist_ok=True)
    (s.data_dir / "exports").mkdir(exist_ok=True)
    return s
