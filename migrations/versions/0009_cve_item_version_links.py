"""Preserve exact CVE relations on immutable item versions."""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "cve_item_version_links",
        sa.Column("item_version_id", sa.Integer(),
                  sa.ForeignKey("item_versions.id"), primary_key=True),
        sa.Column("cve_id", sa.String(64), primary_key=True),
        sa.Column("relation", sa.String(24), nullable=False),
        sa.CheckConstraint(
            "relation IN ('kev','record','reference','title_mention')",
            name="ck_cve_item_version_link_relation",
        ),
    )
    op.create_index(
        "ix_cve_item_version_links_cve_version", "cve_item_version_links",
        ["cve_id", "item_version_id"],
    )
    op.execute(r"""
        INSERT INTO cve_item_version_links (item_version_id, cve_id, relation)
        SELECT item_versions.id, relation.key, relation.value
        FROM item_versions
        CROSS JOIN LATERAL json_each_text(
            CASE
                WHEN json_typeof(item_versions.attributes->'cve_relations') = 'object'
                THEN item_versions.attributes->'cve_relations'
                ELSE '{}'::json
            END
        ) AS relation
        WHERE relation.key ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
          AND length(relation.key) <= 64
          AND relation.value IN ('kev','record','reference','title_mention')
        ON CONFLICT DO NOTHING
    """)


def downgrade():
    op.drop_index("ix_cve_item_version_links_cve_version",
                  table_name="cve_item_version_links")
    op.drop_table("cve_item_version_links")
