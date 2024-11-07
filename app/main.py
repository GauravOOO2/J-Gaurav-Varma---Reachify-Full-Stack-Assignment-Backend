from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel, Field
import jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="TODO API with Auth")

# CORS configuration
origins = [
    "https://j-gaurav-varma-reachify-full-stack-assignment-frontend.vercel.app/",
      "https://j-gaurav-varma-reachify-full-stack-assignment-backend.vercel.app/",  # Replace with your actual frontend URL
    "http://localhost:3000",  # Allow local development
    # Add other origins if needed
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows specific origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

# MongoDB connection
client = MongoClient(os.getenv("MONGODB_URL"))
db = client.todo_db

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # In production, use env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class UserCreate(BaseModel):
    username: str
    password: str

class User(BaseModel):
    username: str

class TodoCreate(BaseModel):
    title: str
    description: str
    completed: bool = False

class Todo(TodoCreate):
    id: str = Field(alias="_id")
    user_id: str

    class Config:
        allow_population_by_field_name = True

class Token(BaseModel):
    access_token: str
    token_type: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = db.users.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

# Auth endpoints
@app.post("/register", response_model=User)
async def register(user: UserCreate):
    if db.users.find_one({"username": user.username}):
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )
    
    hashed_password = get_password_hash(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    
    db.users.insert_one(user_dict)
    return {"username": user.username}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db.users.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Todo endpoints
@app.post("/todos/", response_model=Todo)
async def create_todo(todo: TodoCreate, current_user: dict = Depends(get_current_user)):
    todo_dict = todo.dict()
    todo_dict["user_id"] = current_user["username"]
    todo_dict["created_at"] = datetime.utcnow()
    
    result = db.todos.insert_one(todo_dict)
    todo_dict["_id"] = str(result.inserted_id)
    return todo_dict

@app.get("/todos/", response_model=List[Todo])
async def read_todos(current_user: dict = Depends(get_current_user)):
    todos = []
    for todo in db.todos.find({"user_id": current_user["username"]}):
        todo["_id"] = str(todo["_id"])
        todos.append(todo)
    return todos

@app.get("/todos/{todo_id}", response_model=Todo)
async def read_todo(todo_id: str, current_user: dict = Depends(get_current_user)):
    todo = db.todos.find_one({"_id": ObjectId(todo_id), "user_id": current_user["username"]})
    if todo is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    todo["_id"] = str(todo["_id"])
    return todo

@app.put("/todos/{todo_id}", response_model=Todo)
async def update_todo(todo_id: str, todo: TodoCreate, current_user: dict = Depends(get_current_user)):
    todo_dict = todo.dict()
    result = db.todos.find_one_and_update(
        {"_id": ObjectId(todo_id), "user_id": current_user["username"]},
        {"$set": todo_dict},
        return_document=True
    )
    
    if result is None:
        raise HTTPException(status_code=404, detail="Todo not found")
    
    result["_id"] = str(result["_id"])
    return result

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: str, current_user: dict = Depends(get_current_user)):
    result = db.todos.delete_one({"_id": ObjectId(todo_id), "user_id": current_user["username"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"message": "Todo deleted successfully"}