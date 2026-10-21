from datetime import datetime
from typing import List
from sqlalchemy.orm import Session
from app.database import SessionLocal, IoCRecord, init_db
from app.schemas import NormalizedIoC
from app.collectors.urlhaus import fetch_urlhaus_feed
from app.collectors.feodo import fetch_feodo_ips
from app.collectors.otx import fetch_otx_indicators


def upsert_iocs(db: Session, incoming_iocs: List[NormalizedIoC]) -> dict:
    """
    Inserts new IoCs or updates existing ones with deduplication and multi-feed correlation.
    """
    inserted = 0
    updated = 0

    for item in incoming_iocs:
        existing = db.query(IoCRecord).filter(IoCRecord.ioc_value == item.ioc_value).first()

        if existing:
            existing.last_seen = datetime.utcnow()
            existing.sighting_count += 1
            existing.status = item.status

            # Merge unique tags
            merged_tags = list(set((existing.tags or []) + item.tags))
            existing.tags = merged_tags

            # Merge unique source feeds & boost confidence if corroborated by multiple sources
            feeds = list(set((existing.source_feeds or []) + [item.source_feed]))
            existing.source_feeds = feeds
            if len(feeds) > 1:
                existing.feed_confidence = min(100, max(existing.feed_confidence, item.raw_confidence) + 10)

            updated += 1
        else:
            new_record = IoCRecord(
                ioc_value=item.ioc_value,
                ioc_type=item.ioc_type,
                threat_type=item.threat_type,
                tags=item.tags,
                source_feeds=[item.source_feed],
                status=item.status,
                first_seen=item.first_seen or datetime.utcnow(),
                last_seen=datetime.utcnow(),
                sighting_count=1,
                feed_confidence=item.raw_confidence,
                risk_score=float(item.raw_confidence)
            )
            db.add(new_record)
            inserted += 1

    db.commit()
    return {"inserted": inserted, "updated": updated}


def run_ingestion_pipeline(limit_per_feed: int = 30):
    print("=== STARTING SENTINEL-TIP INGESTION PIPELINE ===")
    init_db()

    all_iocs: List[NormalizedIoC] = []

    # Collect from each feed safely
    for collector in (fetch_urlhaus_feed, fetch_feodo_ips, fetch_otx_indicators):
        try:
            all_iocs.extend(collector(limit=limit_per_feed))
        except Exception as e:
            print(f"[!] Error running {collector.__name__}: {e}")

    db = SessionLocal()
    try:
        stats = upsert_iocs(db, all_iocs)
        total_in_db = db.query(IoCRecord).count()
        print("\n=== INGESTION COMPLETE ===")
        print(f"New IoCs Inserted : {stats['inserted']}")
        print(f"Existing Updated  : {stats['updated']}")
        print(f"Total IoCs in DB  : {total_in_db}")
    finally:
        db.close()


if __name__ == "__main__":
    run_ingestion_pipeline(limit_per_feed=30)