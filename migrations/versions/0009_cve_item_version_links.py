"""Preserve exact CVE relations on immutable item versions.

Legacy rows are derived from their own immutable attributes and recorded parser
provenance using the canonical relation rules. The mutable current-link table is
never consulted to reconstruct history.
"""
from alembic import op
import sqlalchemy as sa
from nous.cve_index import version_cve_relations

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
    connection = op.get_bind()
    link_table = sa.table(
        "cve_item_version_links",
        sa.column("item_version_id", sa.Integer()),
        sa.column("cve_id", sa.String(64)),
        sa.column("relation", sa.String(24)),
    )
    rows = connection.execute(sa.text("""
        SELECT version.id AS item_version_id, version.attributes, version.provenance,
               item.external_id, source.source_key, source.origin AS source_origin
        FROM item_versions AS version
        JOIN items AS item ON item.id = version.item_id
        JOIN sources AS source ON source.id = item.source_id
        ORDER BY version.id
    """).execution_options(stream_results=True)).mappings().yield_per(1000)
    batch = []
    for row in rows:
        relations = version_cve_relations(
            attributes=row["attributes"], provenance=row["provenance"],
            external_id=row["external_id"], source_key=row["source_key"],
            source_origin=row["source_origin"],
        )
        batch.extend({
            "item_version_id": row["item_version_id"],
            "cve_id": cve_id,
            "relation": relation,
        } for cve_id, relation in relations.items())
        if len(batch) >= 1000:
            connection.execute(sa.insert(link_table), batch)
            batch.clear()
    if batch:
        connection.execute(sa.insert(link_table), batch)

    # The deployed roles are deliberately provisioned separately from the
    # migration role. Grant only the operations each service performs, and let
    # installations without optional roles upgrade before provisioning them.
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_runtime') THEN
                EXECUTE format('GRANT INSERT ON TABLE %I.cve_item_version_links TO nous_runtime', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_api') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.cve_item_version_links TO nous_api', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_mcp') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.cve_item_version_links TO nous_mcp', current_schema());
            END IF;
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nous_report_worker') THEN
                EXECUTE format('GRANT SELECT ON TABLE %I.cve_item_version_links TO nous_report_worker', current_schema());
            END IF;
        END
        $$;
    """))


def downgrade():
    op.drop_index("ix_cve_item_version_links_cve_version",
                  table_name="cve_item_version_links")
    op.drop_table("cve_item_version_links")
