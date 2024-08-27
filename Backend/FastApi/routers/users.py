from fastapi import APIRouter , HTTPException
from pydantic import BaseModel

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"message": "No encontrado"}}
)

#Para iniciar el server uvicorn users:router --reload

#Entidad users
class User(BaseModel):
    id: int
    name: str
    surname: str
    url: str
    age: int
    
users_list = [User(id = 1, name="Mathias", surname="Godoy", url="https://mgodoydev.github.io/backend-python", age=22),
         User(id = 2, name="Cesar", surname="Molinas", url="cesar.com", age=22),
         User(id = 3, name="Mathias", surname="Molinas", url="tokeli.com", age=22)
         ]

@router.get("/usersjson")
async def usersjson():
    return [{"name" : "Mathias", "surname" : "Godoy", "url": "https://mgodoydev.github.io/backend-python/", "age": 22}]


@router.get("/")
async def users():
    return users_list

#Path
@router.get("/{id}")
async def user(id: int):    
    return search_user(id)
 
 #Query   
@router.get("/user/")
async def user(id: int):    
    return search_user(id)


@router.post("/user/", status_code= 201)
async def user(user: User):
    if type(search_user(user.id)) == User:
        raise HTTPException(status_code= 404, detail= "El usuario ya existe")
        # return {"Error": "El usuario ya existe"}
 
    users_list.routerend(user)
    return user
        

@router.put("/user/", status_code= 200)
async def user(user: User):
    found = False
    
    for index, saved_user in enumerate(users_list):
        if saved_user.id == user.id:
            if saved_user == user:  # Comparar si el usuario ya existe con los mismos datos
                raise HTTPException(status_code=400, detail="El usuario ya está actualizado con los mismos datos")
            users_list[index] = user  
            found = True
            break
        
    if not found:
        raise HTTPException(status_code=404, detail="No se ha encontrado el usuario para actualizar")
        
    return user

@router.delete("/user/{id}", status_code = 200)
async def user(id:int):
        found = False

        for index, saved_user in enumerate(users_list):
            if saved_user.id == id:
                del users_list[index]
                found = True
                return {"Exito": "El usuario se elimino correctamente"}
        
        if not found:
            raise HTTPException(status_code=404, detail="No se ha encontrado el usuario para eliminar")      
                
def search_user(id: int):
    users = filter(lambda user: user.id == id, users_list )
    try:
        return list(users)[0]
    except:
        return {"Error": "No se ha encontrado el usuario"}