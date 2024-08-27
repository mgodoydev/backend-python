from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone

ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 1
SECRET = "cbe1f791a12b71567014ca62bec73e474176de3d9afb4fcb44f819c95eb06725"

app = FastAPI()

oauth2 = OAuth2PasswordBearer(tokenUrl= "login")

crypt = CryptContext(schemes=["bcrypt"])

class User(BaseModel):
    username: str
    fullname: str
    email: str
    disabled: bool
    
class UserDB(User):
    password: str
    
users_db = {
    "mgodev": {
        "username": "mgodev",
        "fullname": "Mathias Godoy",
        "email": "mathgod@gmail.com",
        "disabled": False,
        "password": "$2a$12$5InRNFAds5CdOtMCPrGVqeiJLCi3.j2J24l28QlHuMx9hh/uaAWQy"
    },
    "mgodev2": {
        "username": "mgodev2",
        "fullname": "Mathias Godoy2",
        "email": "mathgod@gmail.com2",
        "disabled": True,
        "password": "$2a$12$JurJE72Uinssf1kMGFim3..nEF2zkKocN3/.siITIVdTZB07Aqgia"
    },
}

def search_user_db(username: str):
    if username in users_db:
        return UserDB(**users_db[username])
    
def search_user(username: str):
    if username in users_db:
        return UserDB(**users_db[username])

exception =  HTTPException(
            status_code= status.HTTP_404_NOT_FOUND, 
            detail= "Credenciales de autenticacion invalidas", 
            headers={"WWW-Authenticate": "Bearer"})

async def auth_user(token: str = Depends(oauth2)):
    
    try:
        username = jwt.decode(token, SECRET, algorithms=[ALGORITHM]).get("sub")   
        if username is None:
            raise exception
    except JWTError:
            raise exception
    
    return search_user(username)
    
    
async def current_user(user: User = Depends(auth_user)):
    if user.disabled:
        raise HTTPException(
            status_code= status.HTTP_400_BAD_REQUEST, 
            detail= "Usuario inactivo")
        
    return user

@app.post("/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user_db = users_db.get(form.username)
    if not user_db:
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED, 
            detail= "El usuario no es correcto")
          
    user = search_user_db(form.username)
    
    if not crypt.verify(form.password, user.password):
        raise HTTPException(
            status_code= status.HTTP_401_UNAUTHORIZED, 
            detail= "La contraseña no es correcta")
    
    access_token = {"sub": user.username,
                    "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_DURATION)}
        
    return {"access_token" : jwt.encode(access_token,SECRET, algorithm= ALGORITHM) , "token_type" : "bearer"}

@app.get("/users/me")
async def me(user: User = Depends(current_user)):
    return user
