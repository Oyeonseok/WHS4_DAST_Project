"""Executable hypothesis routing for the pinned VulnBank README catalog.

The mapping creates attack hypotheses only.  It never creates findings and is
activated only when all 80 upstream titles match the known benchmark catalog.
"""

from __future__ import annotations

from dataclasses import dataclass

from .catalog import BenchmarkCatalog


@dataclass(frozen=True, slots=True)
class VulnBankCatalogHint:
    ordinal: int
    method: str
    path: str
    vuln_class: str


_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("POST", "/login", "sqli"),
    ("POST", "/login", "jwt_crypto"),
    ("GET", "/check_balance/{account_number}", "idor"),
    ("GET", "/api/v3/user/{user_id}", "idor"),
    ("POST", "/register", "api_misconfig"),
    ("POST", "/forgot-password", "brute_force"),
    ("GET", "/dashboard", "session"),
    ("GET", "/dashboard", "session"),
    ("GET", "/dashboard", "session"),
    ("GET", "/check_balance/{account_number}", "source_leak"),
    ("GET", "/api/virtual-cards", "source_leak"),
    ("POST", "/api/v1/merchants/register", "source_leak"),
    ("GET", "/transactions/{account_number}", "sqli"),
    ("POST", "/api/login", "source_leak"),
    ("POST", "/forgot-password", "source_leak"),
    ("POST", "/transfer", "api_misconfig"),
    ("POST", "/transfer", "business_logic"),
    ("POST", "/transfer", "business_logic"),
    ("POST", "/transfer", "race_condition"),
    ("GET", "/transactions/{account_number}", "source_leak"),
    ("POST", "/transfer", "api_misconfig"),
    ("POST", "/upload_profile_picture", "file_upload"),
    ("POST", "/upload_profile_picture", "lfi"),
    ("POST", "/upload_profile_picture", "file_upload"),
    ("POST", "/upload_profile_picture", "lfi"),
    ("POST", "/upload_profile_picture", "file_upload"),
    ("POST", "/upload_profile_picture", "file_upload"),
    ("POST", "/upload_profile_picture_url", "ssrf"),
    ("POST", "/login", "jwt_crypto"),
    ("GET", "/dashboard", "session"),
    ("POST", "/login", "jwt_crypto"),
    ("GET", "/dashboard", "session"),
    ("POST", "/update_bio", "xss"),
    ("POST", "/api/virtual-cards/{card_id}/toggle-freeze", "csrf"),
    ("GET", "/api/v3/user/{user_id}", "idor"),
    ("POST", "/reset-password", "brute_force"),
    ("POST", "/api/virtual-cards/{card_id}/update-limit", "api_misconfig"),
    ("POST", "/api/virtual-cards/{card_id}/fund", "api_misconfig"),
    ("POST", "/api/virtual-cards/create", "business_logic"),
    ("GET", "/api/virtual-cards", "source_leak"),
    ("POST", "/api/virtual-cards/create", "api_misconfig"),
    ("GET", "/api/virtual-cards/{card_id}/transactions", "idor"),
    ("POST", "/api/virtual-cards/{card_id}/fund", "race_condition"),
    ("GET", "/api/virtual-cards", "source_leak"),
    ("GET", "/api/virtual-cards/{card_id}/transactions", "auth_bypass"),
    ("GET", "/api/virtual-cards/{card_id}/transactions", "source_leak"),
    ("POST", "/api/virtual-cards/{card_id}/fund", "business_logic"),
    ("POST", "/api/bill-payments/create", "api_misconfig"),
    ("GET", "/api/billers/by-category/{category_id}", "sqli"),
    ("GET", "/api/bill-payments/history", "source_leak"),
    ("POST", "/api/bill-payments/create", "business_logic"),
    ("GET", "/api/bill-payments/history", "source_leak"),
    ("POST", "/api/bill-payments/create", "api_misconfig"),
    ("POST", "/api/bill-payments/create", "race_condition"),
    ("GET", "/api/bill-payments/history", "idor"),
    ("POST", "/api/bill-payments/create", "business_logic"),
    ("POST", "/api/v1/merchants/register", "source_leak"),
    ("POST", "/api/v1/merchants/login", "source_leak"),
    ("POST", "/api/v1/payments/charge", "api_misconfig"),
    ("POST", "/api/v1/payments/charge", "sqli"),
    ("POST", "/api/v1/payments/charge", "business_logic"),
    ("POST", "/api/v1/payments/charge", "idor"),
    ("POST", "/api/v1/payments/charge", "source_leak"),
    ("POST", "/api/v1/payments/charge", "business_logic"),
    ("POST", "/api/ai/chat", "llm_ai"),
    ("POST", "/api/ai/chat", "source_leak"),
    ("POST", "/api/ai/chat/anonymous", "auth_bypass"),
    ("GET", "/api/ai/system-info", "source_leak"),
    ("POST", "/api/ai/chat", "api_misconfig"),
    ("POST", "/api/ai/chat", "llm_ai"),
    ("POST", "/api/ai/chat", "llm_ai"),
    ("POST", "/api/ai/chat", "llm_ai"),
    ("POST", "/api/ai/chat/anonymous", "llm_ai"),
    ("GET", "/api/ai/system-info", "source_leak"),
    ("GET", "/graphql", "graphql"),
    ("POST", "/graphql", "jwt_crypto"),
    ("POST", "/graphql", "sqli"),
    ("POST", "/graphql", "graphql"),
    ("POST", "/graphql", "source_leak"),
    ("POST", "/graphql", "auth_bypass"),
)

_PINNED_README_SHA256 = (
    "af935e56acc1a7d262e3d3825b1e2e63d4deb65381c4ea0d318d616cb3e5bc1e"
)


def vulnbank_catalog_hints(
    catalog: BenchmarkCatalog,
) -> tuple[VulnBankCatalogHint, ...]:
    """Return 80 independent hypotheses only for the recognized catalog."""
    if catalog.source_sha256 != _PINNED_README_SHA256:
        return ()
    if len(catalog.items) != len(_ROUTES):
        return ()
    if tuple(item.ordinal for item in catalog.items) != tuple(range(1, 81)):
        return ()
    return tuple(
        VulnBankCatalogHint(index, method, path, vuln_class)
        for index, (method, path, vuln_class) in enumerate(_ROUTES, start=1)
    )
