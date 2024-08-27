#Para iniciar el server uvicorn main:app --reload

from fastapi import APIRouter
from routers import products, users
from fastapi.staticfiles import StaticFiles

app = APIRouter()

#Routers
app.include_router(products.router)
app.include_router(users.router)
app.mount("/static",StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return "Hola FastApi!"

@app.get("/url")
async def url():
    return {"url": "https://mgodoydev.github.io/backend-python/"}