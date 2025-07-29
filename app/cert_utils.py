import logging
import aiofiles
from OpenSSL import crypto
import os
from datetime import datetime, timedelta

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CERTS_DIR = "certs"

async def ensure_certs_dir():
    logger.info("Проверка существования директории certs")
    if not os.path.exists(CERTS_DIR):
        os.makedirs(CERTS_DIR)
        logger.info(f"Создана директория {CERTS_DIR}")

async def create_root_ca(common_name, days=3650):
    logger.info(f"Создание Root CA с CN={common_name} и сроком действия {days} дней")
    try:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.get_subject().CN = common_name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(days * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign")
        ])
        cert.sign(key, "sha256")
        
        ca_cert_path = os.path.join(CERTS_DIR, f"{common_name}_ca.crt")
        ca_key_path = os.path.join(CERTS_DIR, f"{common_name}_ca.key")
        
        async with aiofiles.open(ca_cert_path, "wb") as f:
            await f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        async with aiofiles.open(ca_key_path, "wb") as f:
            await f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        logger.info(f"Root CA создан: сертификат={ca_cert_path}, ключ={ca_key_path}")
        return ca_cert_path, ca_key_path
    except Exception as e:
        logger.error(f"Ошибка при создании Root CA: {str(e)}")
        raise

async def create_certificate(common_name, ca_cert_path, ca_key_path, days=365):
    logger.info(f"Создание сертификата с CN={common_name}, CA={ca_cert_path}, срок действия {days} дней")
    try:
        await ensure_certs_dir()
        
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        req = crypto.X509Req()
        req.get_subject().CN = common_name
        req.set_pubkey(key)
        req.sign(key, "sha256")
        
        async with aiofiles.open(ca_cert_path, "rb") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, await f.read())
        async with aiofiles.open(ca_key_path, "rb") as f:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, await f.read())
        
        cert = crypto.X509()
        cert.set_serial_number(int(datetime.now().timestamp()))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(days * 24 * 60 * 60)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(ca_key, "sha256")
        
        cert_path = os.path.join(CERTS_DIR, f"{common_name}.crt")
        key_path = os.path.join(CERTS_DIR, f"{common_name}.key")
        
        async with aiofiles.open(cert_path, "wb") as f:
            await f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        async with aiofiles.open(key_path, "wb") as f:
            await f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        logger.info(f"Сертификат создан: сертификат={cert_path}, ключ={key_path}")
        return cert_path, key_path
    except Exception as e:
        logger.error(f"Ошибка при создании сертификата: {str(e)}")
        raise