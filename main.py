
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status,Request
from fastapi.staticfiles import StaticFiles
from sqlmodel import SQLModel, Field, create_engine, Session, select
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from typing import Optional, List, Dict
from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, Sequence, Integer
from fastapi.concurrency import run_in_threadpool
import os
import ipaddress
import json
from sqlalchemy import func

from honeypot import router as honeypot_router


SECRET_KEY = os.environ.get("SECRET_KEY", "demo-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Chat App (FastAPI + WebSocket + sqlite)")
app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(honeypot_router)
class Users(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None,
        sa_column=Column("id", Integer, Sequence("users_seq"), primary_key=True)
    )
    username: str = Field(sa_column=Column(String(255), unique=True, index=True))
    email: Optional[str] = Field(default=None, sa_column=Column(String(255)))
    hashed_password: str = Field(sa_column=Column(String(255), nullable=False))

class Messages(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None,
        sa_column=Column("id", Integer, Sequence("messages_seq"), primary_key=True)
    )
    sender_id: Optional[int] = Field(default=None, index=True)
    sender_username: str = Field(sa_column=Column(String(255)))
    content: str = Field(sa_column=Column(String(255)))
    timestamp: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime))

class Contacts(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None,
        sa_column=Column("id", Integer, Sequence("contacts_seq"), primary_key=True)
    )
    owner_id: int = Field(index=True)          
    phone: str = Field(sa_column=Column(String(255)))
    name: str = Field(sa_column=Column(String(255)))


DATABASE_URL = "sqlite:///./chat.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# ---------- نماذج Pydantic ----------
class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class ContactCreate(BaseModel):
    phone: str
    name: str

def encrypt(text):
    key='maran'
    text=text.upper()
    nums=[]
    for ch in text:
        if ch == " ":
            val=26
        else:
            val=ord(ch)-ord('A')
        nums.append(val) 
      
    while len(nums)%3!=0:
        nums.append(26)
    matrix=[]   
    for i in range(0,len(nums),3):
        row=nums[i:i+3]
        matrix.append(row)
    
    A=0
    for ch in key:
        A+=ord(ch)
    B=(A%25)+1
    
    shifted_matrix=[]
    for row in matrix:
        new_row=[]
        for x in row:
            rotated=((x >> 1) | ((x & 1) << 4))
            new_row.append(rotated)
        shifted_matrix.append(new_row)
    
    encrypted_matrix=[]
    for i,row in enumerate(shifted_matrix):
        new_row=[]
        for j,x in enumerate(row):
            pos=i*3+(j+1)
            new_val=(x+A+B+pos)%27
            new_row.append(new_val)
        encrypted_matrix.append(new_row)
    
    encrypted_text=""
    for row in encrypted_matrix:
        for x in row:
            encrypted_text+=chr(x+ord('A'))
    return encrypted_text

def decrypt(cipher_text):
    key='maran'
    cipher_text=cipher_text.upper()
    
    cipher_nums=[]
    for ch in cipher_text:
        if ch == " ":
            cipher_val=26
        else:
            cipher_val=ord(ch)-ord('A')
        cipher_nums.append(cipher_val)
    
    A=0
    for ch in key:
        A+=ord(ch)
    B=(A%25)+1
    
    cipher_matrix=[]   
    for i in range(0,len(cipher_nums),3):
        row=cipher_nums[i:i+3]
        cipher_matrix.append(row)
    
    after_math=[]
    for i,row in enumerate(cipher_matrix):
        new_row=[]
        for j,x in enumerate(row):
            pos=i*3+(j+1)
            original_val=(x-A-B-pos)%27
            new_row.append(original_val)
        after_math.append(new_row)
    
    after_shift=[]
    for row in after_math:
        new_row=[]
        for x in row:
            rotated=((x << 1) & 0b11111) | (x >> 4)
            original_val=rotated
            new_row.append(original_val)
        after_shift.append(new_row)
    
    plain_text=""
    for row in after_shift:
        for val in row:
            if val == 26:
                plain_text += " "
            else:
                plain_text+=chr(val+ord('A'))
    
    
  
    return plain_text.title()

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_username(username: str) -> Optional[Users]:
    with Session(engine) as session:
        statement = select(Users).where(Users.username == username)
        return session.exec(statement).first()

def create_user(user_create: UserCreate) -> Users:
    user = Users(username=user_create.username, email=user_create.email, hashed_password=get_password_hash(user_create.password))
    with Session(engine) as session:
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

def save_message(sender_id: int, sender_username: str, content: str) -> Messages:
    encrypted=encrypt(content)
    msg = Messages(sender_id=sender_id, sender_username=sender_username, content=encrypted)
    with Session(engine) as session:
        session.add(msg)
        session.commit()
        session.refresh(msg)
        return msg

def get_last_messages(limit: int = 50) -> List[Messages]:
    with Session(engine) as session:
        statement = select(Messages).order_by(Messages.timestamp.desc()).limit(limit)
        result = session.exec(statement).all()
        return list(reversed(result))

def create_contact(user_id: int, data: ContactCreate) -> Contacts:
    c = Contacts(owner_id=user_id, phone=data.phone, name=data.name)
    with Session(engine) as session:
        session.add(c)
        session.commit()
        session.refresh(c)
        return c

def get_contacts(user_id: int) -> List[Contacts]:
    with Session(engine) as session:
        return session.exec(select(Contacts).where(Contacts.owner_id == user_id)).all()
def count_public_messages() -> int:
    with Session(engine) as session:
        statement = select(func.count()).select_from(Messages)
        return session.exec(statement).one()

@app.post("/register")
async def register(user: UserCreate):
    existing = await run_in_threadpool(get_user_by_username, user.username)
    if existing:
        raise HTTPException(status_code=400, detail="اسم المستخدم موجود مسبقًا")
    new_user = await run_in_threadpool(create_user, user)
    return {"id": new_user.id, "username": new_user.username}

@app.post("/login")
async def login(payload: UserLogin):
    user = await run_in_threadpool(get_user_by_username, payload.username)
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="بيانات اعتماد غير صحيحة")
    token = create_access_token({"sub": user.username, "user_id": user.id})
    return {"access_token": token, "token_type": "bearer", "username": user.username, "user_id": user.id}

@app.get("/messages")
async def messages(limit: int = 100):
    x=0
    msgs = await run_in_threadpool(get_last_messages, limit)
    return [
        {    
            "id": m.id,
            "sender_id": m.sender_id,
            "sender_username": m.sender_username,
            "content": decrypt(m.content),
            "timestamp": m.timestamp.strftime("%H:%M %p"),
        } for m in msgs
        
    ]
@app.get("/users")
async def get_users():
    def fetch_users():
        with Session(engine) as session:
            users = session.exec(select(Users)).all()
            return [
                {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email
                } for u in users
            ]
    return await run_in_threadpool(fetch_users)
@app.get("/messages/count")
async def messages_count(token: str, other_user_id: Optional[int] = None):
    user_info = decode_token_or_none(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Unauthorized")
    cnt = await run_in_threadpool(count_public_messages)
    return {"count": cnt}


@app.post("/contacts")
async def add_contact(data: ContactCreate, token: str):
    user_info = decode_token_or_none(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Unauthorized")
    c = await run_in_threadpool(create_contact, user_info["user_id"], data)
    return {"id": c.id, "name": c.name, "phone": c.phone}

@app.get("/contacts")
async def list_contacts(token: str):
    user_info = decode_token_or_none(token)
    if not user_info:
        raise HTTPException(status_code=401, detail="Unauthorized")
    cs = await run_in_threadpool(get_contacts, user_info["user_id"])
    return [{"id": c.id, "name": c.name, "phone": c.phone} for c in cs]


@app.get("/users/count")
async def users_count() -> dict:
    with Session(engine) as session:
        count = session.exec(select(func.count()).select_from(Users)).one()
        return {"count": count}
#===================حذف مستخدم
@app.delete("/admin/user/{user_id}")
async def delete_user(user_id: int):
    with Session(engine) as session:
        user = session.get(Users, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        session.delete(user)
        session.commit()
        return {"detail": "User deleted"}

# حذف رسالة
@app.delete("/admin/message/{message_id}")
async def delete_message(message_id: int):
    with Session(engine) as session:
        msg = session.get(Messages, message_id)
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        session.delete(msg)
        session.commit()
        return {"detail": "Message deleted"}

# تعديل رسالة
class MessageUpdate(BaseModel):
    content: str

@app.put("/admin/message/{message_id}")
async def update_message(message_id: int, data: MessageUpdate):
    with Session(engine) as session:
        msg = session.get(Messages, message_id)
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        msg.content = encrypt(data.content)  # حفظها مشفرة
        session.add(msg)
        session.commit()
        session.refresh(msg)
        return {"id": msg.id, "content": decrypt(msg.content)}


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.ws_to_user: Dict[WebSocket, Dict] = {}

    async def connect(self, websocket: WebSocket, user_info: Dict):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.ws_to_user[websocket] = user_info

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.ws_to_user:
            del self.ws_to_user[websocket]

    async def broadcast(self, message: dict):
        to_remove = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                to_remove.append(connection)
        for c in to_remove:
            self.disconnect(c)

manager = ConnectionManager()


def decode_token_or_none(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        if username is None or user_id is None:
            return None
        return {"username": username, "user_id": user_id}
    except JWTError:
        return None


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    user_info = decode_token_or_none(token) if token else None
    if not user_info:
        await websocket.accept()
        await websocket.send_json({"type": "system", "message": "Unauthorized"})
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, user_info)
    await manager.broadcast({"type": "system", "message": f"{user_info['username']} متصل"})

    try:
        while True:
            text = await websocket.receive_text()
            payload = json.loads(text)

            content = payload.get("content", "").strip()
            to_user = payload.get("to_user")

            if not content:
                continue

            if to_user:
                msg_data = {
                    "type": "private",
                    "from": user_info["username"],
                    "to": to_user,
                    "content": content,
                    "timestamp": datetime.utcnow().isoformat()
                }
                for ws, info in manager.ws_to_user.items():
                    if info["username"] in [user_info["username"], to_user]:
                        await ws.send_json(msg_data)
            else:
                saved = await run_in_threadpool(save_message, user_info["user_id"], user_info["username"], content)
                msg_data = {
                    "type": "message",
                    "id": saved.id,
                    "sender_id": saved.sender_id,
                    "sender_username": saved.sender_username,
                    "content": decrypt(saved.content),
                    "timestamp": saved.timestamp.strftime("%H:%M %p")
                }
                await manager.broadcast(msg_data)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast({"type": "system", "message": f"{user_info['username']} غادر"})
