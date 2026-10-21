import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from dotenv import load_dotenv

load_dotenv()

# Ensures data directory exists for SQLite
os.makedirs("data", exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/sentinel_tip.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    """
    User model for enterprise authentication and subscription management.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    subscription_status = Column(String, default="inactive")  # inactive, active, trial
    stripe_customer_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class IoCRecord(Base):
    """
    Database model storing normalized, deduplicated, and ML-scored Indicators of Compromise.
    """
    __tablename__ = "ioc_records"

    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String, unique=True, index=True, nullable=False)
    ioc_type = Column(String, index=True, nullable=False)          # url, ipv4, domain, sha256
    threat_type = Column(String, nullable=False)                   # malware_download, botnet_c2, phishing
    tags = Column(JSON, default=list)                              # Malware families / tags
    source_feeds = Column(JSON, default=list)                      # Feeds reporting this IoC
    status = Column(String, default="online")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    sighting_count = Column(Integer, default=1)

    # ML & Risk Scoring fields
    feed_confidence = Column(Integer, default=75)                  # 0 - 100
    ml_malicious_prob = Column(Float, nullable=True)               # 0.0 - 1.0 (XGBoost)
    is_anomaly = Column(Integer, default=0)                        # 1 if Isolation Forest outlier, else 0
    risk_score = Column(Float, default=75.0)                       # Unified 0 - 100 platform score


def init_db():
    Base.metadata.create_all(bind=engine)