from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from models import Users
from passlib.context import CryptContext
from database import SessionLocal
from typing import Annotated
from starlette import status
from jose import jwt, JWTError
from datetime import timedelta, datetime, timezone

router = APIRouter(prefix='/auth', tags=['auth'])

SECRET_KEY = "912160ae8cf6481ffbff568e07acb717a37cdcd8f81728915542e11386996bce"
ALGORITHM = "HS256"

class Token(BaseModel):
    access_token: str
    token_type: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)] 

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

class UserRequest(BaseModel):
    username: str=Field(min_length=3)
    email: str=Field(min_length=3)
    first_name: str=Field(min_length=3)
    last_name: str=Field(min_length=3)
    password: str=Field(min_length=3)
    role: str=Field(min_length=3)

def authenticate_user(db: db_dependency, username: str, password: str):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {"sub": username, "id": user_id, "exp": datetime.now(timezone.utc) + expires_delta} 
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(oauth_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        usename: str = payload.get('sub')
        user_id: int = payload.get('id')
        if usename is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='could not validate user')
        return {'username': usename, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='could not validate user')


@router.post('/', status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, user_request: UserRequest):
    user_model = Users(
        username=user_request.username,
        email=user_request.email,
        first_name=user_request.first_name,
        last_name=user_request.last_name,
        hashed_password=bcrypt_context.hash(user_request.password),
        role=user_request.role,
        is_active=True
    )

    db.add(user_model)
    db.commit()

    return user_model

@router.post('/token/', response_model=Token)
async def login_for_access_token(db: db_dependency, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(db, form_data.username, form_data.password)
    if user:
        token = create_access_token(user.username, user.id, timedelta(minutes=20))
        return {'access_token': token, 'token_type': 'bearer'}
        
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='could not validate user')
