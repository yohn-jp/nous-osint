"""Migration 0009 reconstructs legacy CVE links from immutable versions."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import uuid

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    JSON,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    insert,
    select,
    text,
)


pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL required")


def test_0009_backfill_uses_recorded_adapter_after_source_adapter_changes():
    dsn = os.environ["DATABASE_URL"]
    admin_engine = create_engine(dsn)
    schema = "cve_version_migration_" + uuid.uuid4().hex[:12]
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_engine(dsn, connect_args={"options": f"-csearch_path={schema}"})
    metadata = MetaData()
    sources = Table(
        "sources", metadata,
        Column("id", Integer, primary_key=True),
        Column("source_key", String(100), nullable=False),
        Column("kind", String(20), nullable=False),
        Column("origin", String(16), nullable=False),
        Column("adapter", String(40), nullable=False),
    )
    items = Table(
        "items", metadata,
        Column("id", Integer, primary_key=True),
        Column("source_id", ForeignKey("sources.id"), nullable=False),
        Column("external_id", Text, nullable=False),
    )
    versions = Table(
        "item_versions", metadata,
        Column("id", Integer, primary_key=True),
        Column("item_id", ForeignKey("items.id"), nullable=False),
        Column("attributes", JSON, nullable=False),
        Column("provenance", JSON, nullable=False),
    )
    try:
        metadata.create_all(engine)
        with engine.begin() as connection:
            old_source_id = connection.execute(insert(sources).values(
                source_key="legacy-vendor", kind="rss", origin="official",
                adapter="json_v1",
            ).returning(sources.c.id)).scalar_one()
            old_item_id = connection.execute(insert(items).values(
                source_id=old_source_id, external_id="legacy-advisory",
            ).returning(items.c.id)).scalar_one()
            old_version_id = connection.execute(insert(versions).values(
                item_id=old_item_id,
                attributes={"title": "Legacy bulletin references CVE-2026-12345"},
                provenance={"adapter": "rss_v1"},
            ).returning(versions.c.id)).scalar_one()

            cisa_source_id = connection.execute(insert(sources).values(
                source_key="cisa-kev", kind="json_api", origin="official",
                adapter="json_v2",
            ).returning(sources.c.id)).scalar_one()
            cisa_item_id = connection.execute(insert(items).values(
                source_id=cisa_source_id, external_id="CVE-2026-67890",
            ).returning(items.c.id)).scalar_one()
            cisa_version_id = connection.execute(insert(versions).values(
                item_id=cisa_item_id,
                attributes={"title": "CISA KEV record", "vulnerability": {
                    "cve_id": "CVE-2026-67890", "known_exploited": True,
                }},
                provenance={"adapter": "cisa_kev_v1"},
            ).returning(versions.c.id)).scalar_one()

            migration_path = (Path(__file__).resolve().parents[1] / "migrations" /
                              "versions" / "0009_cve_item_version_links.py")
            spec = importlib.util.spec_from_file_location("cve_link_migration", migration_path)
            assert spec is not None and spec.loader is not None
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)
            context = MigrationContext.configure(connection)
            with Operations.context(context):
                migration.upgrade()

            rows = connection.execute(select(
                text("item_version_id"), text("cve_id"), text("relation"),
            ).select_from(text("cve_item_version_links"))).all()

        assert set(rows) == {
            (old_version_id, "CVE-2026-12345", "title_mention"),
            (cisa_version_id, "CVE-2026-67890", "kev"),
        }
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()
