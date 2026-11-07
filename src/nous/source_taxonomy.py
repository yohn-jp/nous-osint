"""Stable, reviewed source taxonomy shared by collection and report selection.

Category identifies a source's editorial role; item_kind identifies the record schema.
Existing catalog rows without a category use a deterministic compatibility mapping.
"""
SOURCE_CATEGORIES = {
    "vulnerability": "脆弱性データベース",
    "advisory": "公式アドバイザリ",
    "threat_research": "脅威・攻撃調査",
    "security_news": "セキュリティ動向",
    "industry": "企業・業界動向",
    "careers": "セキュリティ求人",
}
KIND_CATEGORY = {
    "vulnerability": "vulnerability",
    "advisory": "advisory",
    "news": "security_news",
    "company_update": "industry",
    "job_posting": "careers",
}


def source_category(config: dict, item_kind: str) -> str:
    category = config.get("category")
    return category if category in SOURCE_CATEGORIES else KIND_CATEGORY[item_kind]
