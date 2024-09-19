from fastapi import FastAPI, Depends, HTTPException, Path
from models import Todos, Base
from database import engine, SessionLocal
from routers import auth, todos

app = FastAPI()

Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(todos.router)
