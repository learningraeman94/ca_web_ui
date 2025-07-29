from fastapi import FastAPI, Request, Form, HTTPException, File, UploadFile, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.database import init_db, save_certificate, get_certificates, save_root_ca, get_root_cas, get_db, RootCA
from app.cert_utils import create_root_ca, create_certificate
from sqlalchemy.orm import Session
import logging
import os

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

@app.on_event("startup")
def on_startup():
    logger.info("Инициализация базы данных")
    init_db()

@app.get("/", response_class=HTMLResponse, tags=["pages"])
async def show_index(request: Request):
    logger.info("Отображение главной страницы")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/certificates", response_class=HTMLResponse, tags=["pages"])
async def show_certificates(request: Request, db: Session = Depends(get_db)):
    logger.info("Отображение списка сертификатов")
    certs = get_certificates(db)
    return templates.TemplateResponse("certificates.html", {"request": request, "certificates": certs})

@app.get("/create-cert", response_class=HTMLResponse, tags=["pages"])
async def show_create_cert_form(request: Request, db: Session = Depends(get_db)):
    logger.info("Отображение формы создания сертификата")
    root_cas = get_root_cas(db)
    return templates.TemplateResponse("create_cert.html", {"request": request, "root_cas": root_cas})

@app.post("/create-cert", response_class=HTMLResponse, tags=["actions"])
async def create_cert(
    request: Request,
    common_name: str = Form(...),
    ca_cert_id: int = Form(...),
    days: int = Form(...),
    db: Session = Depends(get_db)
):
    logger.info(f"Создание сертификата с CN={common_name}, ca_cert_id={ca_cert_id}, days={days}")
    try:
        root_ca = db.query(RootCA).filter(RootCA.id == ca_cert_id).first()
        if not root_ca or not os.path.exists(root_ca.cert_path) or not os.path.exists(root_ca.key_path):
            logger.error("Недействительный сертификат или ключ CA")
            raise HTTPException(status_code=400, detail="Недействительный сертификат или ключ CA")
        
        cert_path, key_path = await create_certificate(common_name, root_ca.cert_path, root_ca.key_path, days)
        save_certificate(db, common_name, cert_path, key_path, root_ca.cert_path)
        logger.info("Сертификат успешно создан")
        return templates.TemplateResponse("index.html", {"request": request, "message": "Сертификат успешно создан"})
    except Exception as e:
        logger.error(f"Ошибка при создании сертификата: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка при создании сертификата: {str(e)}")

@app.get("/manage-root-ca", response_class=HTMLResponse, tags=["pages"])
async def show_manage_root_ca_form(request: Request):
    logger.info("Отображение формы управления Root CA")
    return templates.TemplateResponse("manage_root_ca.html", {"request": request})

@app.post("/manage-root-ca/create", response_class=HTMLResponse, tags=["actions"])
async def create_root_ca(
    request: Request,
    common_name: str = Form(...),
    days: int = Form(...),
    db: Session = Depends(get_db)
):
    logger.info(f"Создание Root CA с CN={common_name}, days={days}")
    try:
        # Проверяем, что common_name не содержит недопустимых символов
        if not common_name or any(c in common_name for c in '<>:"/\\|?*'):
            logger.error("Недопустимое общее имя")
            raise HTTPException(status_code=400, detail="Недопустимое общее имя")
        
        # Асинхронный вызов
        ca_cert_path, ca_key_path = await create_root_ca(common_name, days)
        save_root_ca(db, common_name, ca_cert_path, ca_key_path)
        logger.info("Root CA успешно создан")
        return templates.TemplateResponse("index.html", {"request": request, "message": "Root CA успешно создан"})
    except Exception as e:
        logger.error(f"Ошибка при создании Root CA: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка при создании Root CA: {str(e)}")

@app.post("/manage-root-ca/upload", response_class=HTMLResponse, tags=["actions"])
async def upload_root_ca(
    request: Request,
    common_name: str = Form(...),
    ca_cert: UploadFile = File(...),
    ca_key: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    logger.info(f"Загрузка Root CA с CN={common_name}")
    try:
        if not os.path.exists("certs"):
            os.makedirs("certs")
            logger.info("Создана директория certs")
        
        ca_cert_path = os.path.join("certs", f"{common_name}_ca.crt")
        ca_key_path = os.path.join("certs", f"{common_name}_ca.key")
        
        async with aiofiles.open(ca_cert_path, "wb") as f:
            await f.write(await ca_cert.read())
        async with aiofiles.open(ca_key_path, "wb") as f:
            await f.write(await ca_key.read())
        
        async with aiofiles.open(ca_cert_path, "rb") as f:
            crypto.load_certificate(crypto.FILETYPE_PEM, await f.read())
        async with aiofiles.open(ca_key_path, "rb") as f:
            crypto.load_privatekey(crypto.FILETYPE_PEM, await f.read())
        
        save_root_ca(db, common_name, ca_cert_path, ca_key_path)
        logger.info("Root CA успешно загружен")
        return templates.TemplateResponse("index.html", {"request": request, "message": "Root CA успешно загружен"})
    except Exception as e:
        logger.error(f"Ошибка при загрузке Root CA: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Недействительный сертификат или ключ CA: {str(e)}")