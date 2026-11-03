"""One-off, idempotent maintenance commands run after reviewed migrations."""

from sqlalchemy import select
from .db import session_factory
from .models import Item, ItemVersion, Source
from .registry import load_registry
from .runtime import parse_timestamp


def backfill_item_metadata():
    organizations = {source.id: source.organization for source in load_registry()}
    count = 0
    with session_factory()() as db:
        rows = db.execute(
            select(Item, Source, ItemVersion)
            .join(Source, Item.source_id == Source.id)
            .join(ItemVersion, (ItemVersion.item_id == Item.id) &
                  (ItemVersion.version == Item.current_version))
        )
        for item, source, version in rows:
            item.organization = organizations.get(source.source_key)
            item.published_at = parse_timestamp(version.attributes.get("published"))
            item.updated_at = parse_timestamp(version.attributes.get("updated"))
            count += 1
        db.commit()
    return count


if __name__ == "__main__":
    print(backfill_item_metadata())
