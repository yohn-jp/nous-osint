"""Index CVE identity across item sources; backfill current legacy observations.

KEV is a source-backed assertion, not a property guessed from CVE descriptions.
Existing item and item_version rows remain untouched.
"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "cve_item_links",
        sa.Column("item_id", sa.Integer(), sa.ForeignKey("items.id"), primary_key=True),
        sa.Column("cve_id", sa.String(64), primary_key=True),
        sa.Column("relation", sa.String(24), nullable=False),
        sa.CheckConstraint(
            "relation IN ('kev','record','reference','title_mention')",
            name="ck_cve_link_relation"
        ),
    )
    op.create_index("ix_cve_item_links_cve_id", "cve_item_links", ["cve_id"])

    # Canonical CVE records and CISA KEV entries predate the index: index
    # them without modifying source observations or reconstructing records.
    op.execute(r"""
        INSERT INTO cve_item_links (item_id, cve_id, relation)
        SELECT i.id, i.external_id,
               CASE WHEN s.adapter = 'cisa_kev_v1' THEN 'kev'
                    ELSE 'record' END
        FROM items AS i
        JOIN sources AS s ON s.id = i.source_id
        WHERE i.external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
          AND length(i.external_id) <= 64
          AND i.kind IN ('vulnerability', 'advisory')
          AND (s.adapter <> 'cisa_kev_v1' OR i.state = 'current')
        ON CONFLICT DO NOTHING
    """)
    # Deterministic title-only associations for already stored advisories.
    # They are never promoted to an authoritative exploitation assertion.
    op.execute(r"""
        INSERT INTO cve_item_links (item_id, cve_id, relation)
        SELECT i.id, hits.cve_id[1], 'title_mention'
        FROM items AS i
        CROSS JOIN LATERAL regexp_matches(
            i.title, '\m(CVE-[0-9]{4}-[0-9]{4,})\M', 'g'
        ) AS hits(cve_id)
        WHERE i.kind <> 'job_posting'
          AND length(hits.cve_id[1]) <= 64
        ON CONFLICT DO NOTHING
    """)


def downgrade():
    op.drop_index("ix_cve_item_links_cve_id", table_name="cve_item_links")
    op.drop_table("cve_item_links")
