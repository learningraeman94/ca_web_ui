from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = "sqlite:///ca_database.db"
Base = declarative_base()

class Certificate(Base):
    __tablename__ = "certificates"
    id = Column(Integer, primary_key=True, index=True)
    common_name = Column(String, nullable=False)
    cert_path = Column(String, nullable=False)
    key_path = Column(String, nullable=False)
    ca_cert_path = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class RootCA(Base):
    __tablename__ = "root_cas"
    id = Column(Integer, primary_key=True, index=True)
    common_name = Column(String, nullable=False)
    cert_path = Column(String, nullable=False)
    key_path = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def save_certificate(db, common_name, cert_path, key_path, ca_cert_path):
    cert = Certificate(
        common_name=common_name,
        cert_path=cert_path,
        key_path=key_path,
        ca_cert_path=ca_cert_path
    )
    db.add(cert)
    db.commit()
    db.refresh(cert)
    return cert

def save_root_ca(db, common_name, cert_path, key_path):
    root_ca = RootCA(
        common_name=common_name,
        cert_path=cert_path,
        key_path=key_path
    )
    db.add(root_ca)
    db.commit()
    db.refresh(root_ca)
    return root_ca

def get_certificates(db):
    return db.query(Certificate).all()

def get_root_cas(db):
    return db.query(RootCA).all()