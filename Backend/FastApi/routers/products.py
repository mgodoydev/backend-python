from fastapi import APIRouter

router = APIRouter(
    prefix="/products",
    tags=["products"],
    responses={404: {"message": "No encontrado"}}
)

products_lists = ["Producto1", "Producto2", "Producto3", "Producto4", "Producto5"]

@router.get("/products")
async def products():
    return products_lists

router.get("/{id}")
async def products(id:int):
    return products[id]
