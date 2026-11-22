"""Saree Business API: role-based inventory, sales, and audit history."""
import os, sqlite3, secrets, hashlib, smtplib, ssl, urllib.request, urllib.parse, base64, json
from email.message import EmailMessage
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
from pwdlib import PasswordHash

load_dotenv()
DB = os.getenv('DATABASE_PATH', str(Path(__file__).parent / 'saree_business.db'))
SECRET = os.getenv('SECRET_KEY', 'DEV_ONLY_CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT')
ALGORITHM = 'HS256'
ph = PasswordHash.recommended()
app = FastAPI(title='SareeFlow API', version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=os.getenv('CORS_ORIGINS','http://localhost:5173').split(','), allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
security = HTTPBearer()

def connection():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=20000')
    return db

@contextmanager
def tx():
    db = connection()
    try:
        db.execute('BEGIN IMMEDIATE')
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def now(): return datetime.now(timezone.utc).isoformat()
def asdict(row): return dict(row) if row else None

def initialize():
    with tx() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','worker')), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sarees (id INTEGER PRIMARY KEY, name TEXT NOT NULL, sku TEXT NOT NULL UNIQUE, category TEXT NOT NULL DEFAULT '', price REAL NOT NULL CHECK(price>=0), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, saree_id INTEGER NOT NULL REFERENCES sarees(id), worker_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL CHECK(kind IN ('collected','sold')), quantity INTEGER NOT NULL CHECK(quantity>0), amount REAL NOT NULL DEFAULT 0 CHECK(amount>=0), payment_method TEXT CHECK(payment_method IN ('cash','upi','online') OR payment_method IS NULL), transaction_id TEXT, maker_name TEXT, notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, actor_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_entries_saree ON entries(saree_id);
        CREATE INDEX IF NOT EXISTS idx_entries_worker ON entries(worker_id);
        """)
        cols={r['name'] for r in db.execute('PRAGMA table_info(users)')}
        for col in ('email','phone'):
            if col not in cols: db.execute(f'ALTER TABLE users ADD COLUMN {col} TEXT')
        db.executescript("""
        CREATE TABLE IF NOT EXISTS makers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE, phone TEXT, notes TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS maker_orders (id INTEGER PRIMARY KEY, maker_id INTEGER NOT NULL REFERENCES makers(id), saree_id INTEGER NOT NULL REFERENCES sarees(id), ordered INTEGER NOT NULL CHECK(ordered>0), notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS maker_deliveries (id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES maker_orders(id), worker_id INTEGER NOT NULL REFERENCES users(id), quantity INTEGER NOT NULL CHECK(quantity>0), delivered_at TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS password_otps (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), digest TEXT NOT NULL, expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_deliveries_order ON maker_deliveries(order_id);
        """)
        db.executescript("""
        CREATE TABLE IF NOT EXISTS maker_daily_targets (
          maker_id INTEGER PRIMARY KEY REFERENCES makers(id), expected_total INTEGER NOT NULL DEFAULT 0 CHECK(expected_total>=0), updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS maker_daily_receipts (
          id INTEGER PRIMARY KEY, maker_id INTEGER NOT NULL REFERENCES makers(id), worker_id INTEGER NOT NULL REFERENCES users(id),
          saree_name TEXT NOT NULL, quantity INTEGER NOT NULL CHECK(quantity>0), received_date TEXT NOT NULL,
          notes TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_daily_maker_date ON maker_daily_receipts(maker_id,received_date);
        """)
        if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            users=[('Admin One','admin1','admin'),('Admin Two','admin2','admin')] + [(f'Worker {i}',f'worker{i}','worker') for i in range(1,11)]
            for name,username,role in users:
                db.execute('INSERT INTO users(name,username,password_hash,role,created_at) VALUES(?,?,?,?,?)',(name,username,ph.hash('ChangeMe@123'),role,now()))
initialize()

class Login(BaseModel): username:str; password:str; role:Literal['admin','worker']|None=None
class UserCreate(BaseModel): name:str=Field(min_length=2,max_length=80); username:str=Field(min_length=3,max_length=40); password:str=Field(min_length=8); role:Literal['admin','worker']; email:str|None=None; phone:str|None=None
class UserPatch(BaseModel): name:str|None=None; password:str|None=None; active:bool|None=None; email:str|None=None; phone:str|None=None
class SareeCreate(BaseModel): name:str=Field(min_length=2,max_length=100); sku:str=Field(min_length=2,max_length=40); category:str=''; price:float=Field(ge=0)
class SareePatch(BaseModel): name:str|None=None; sku:str|None=None; category:str|None=None; price:float|None=Field(default=None,ge=0); active:bool|None=None
class EntryCreate(BaseModel):
    saree_id:int
    kind:Literal['collected','sold']
    quantity:int=Field(gt=0)
    amount:float=Field(default=0,ge=0)
    payment_method:Literal['cash','upi','online']|None=None
    transaction_id:str|None=None
    maker_name:str|None=None
    notes:str=''
    worker_id:int|None=None
    @field_validator('transaction_id','maker_name')
    @classmethod
    def strip_optional(cls,v): return v.strip() or None if v is not None else None
class EntryPatch(BaseModel):
    saree_id:int|None=None
    kind:Literal['collected','sold']|None=None
    quantity:int|None=Field(default=None,gt=0)
    amount:float|None=Field(default=None,ge=0)
    payment_method:Literal['cash','upi','online']|None=None
    transaction_id:str|None=None
    maker_name:str|None=None
    notes:str|None=None
    worker_id:int|None=None

def user_public(u): return {k:u[k] for k in ('id','name','username','role','active','created_at','email','phone')}
def current(credentials:HTTPAuthorizationCredentials=Depends(security)):
    try: payload=jwt.decode(credentials.credentials,SECRET,algorithms=[ALGORITHM]); uid=int(payload['sub'])
    except Exception: raise HTTPException(401,'Invalid or expired session')
    with connection() as db: u=db.execute('SELECT * FROM users WHERE id=? AND active=1',(uid,)).fetchone()
    if not u: raise HTTPException(401,'Account inactive or missing')
    return dict(u)
def admin(u=Depends(current)):
    if u['role']!='admin': raise HTTPException(403,'Admins only')
    return u

def audit(db,actor,action,details): db.execute('INSERT INTO audit(actor_id,action,details,created_at) VALUES(?,?,?,?)',(actor,action,details,now()))
def stock(db,saree_id,exclude=None):
    q="SELECT COALESCE(SUM(CASE WHEN kind='collected' THEN quantity ELSE -quantity END),0) FROM entries WHERE saree_id=?"
    args=[saree_id]
    if exclude is not None: q+=' AND id<>?';args.append(exclude)
    return db.execute(q,args).fetchone()[0]
def check_entry(db,data,exclude=None):
    saree=db.execute('SELECT * FROM sarees WHERE id=?',(data['saree_id'],)).fetchone()
    if not saree: raise HTTPException(404,'Saree not found')
    worker=db.execute('SELECT role FROM users WHERE id=?',(data['worker_id'],)).fetchone()
    if not worker or worker['role']!='worker': raise HTTPException(400,'Select a worker account')
    if data['kind']=='sold':
        if not data.get('payment_method'): raise HTTPException(400,'Payment method required for sales')
        if stock(db,data['saree_id'],exclude)<data['quantity']: raise HTTPException(400,'Not enough stock for this sale')
    else:
        if not data.get('maker_name'): raise HTTPException(400,'Maker name required for collection')
        data['payment_method']=None;data['transaction_id']=None
    if data.get('payment_method')=='cash': data['transaction_id']=None

def validate_stock(db):
    bad=db.execute("SELECT saree_id FROM entries GROUP BY saree_id HAVING SUM(CASE WHEN kind='collected' THEN quantity ELSE -quantity END)<0").fetchone()
    if bad: raise HTTPException(400,'This change would make stock negative')

@app.get('/api/health')
def health(): return {'status':'ok'}
@app.post('/api/auth/login')
def login(body:Login):
    with connection() as db: u=db.execute('SELECT * FROM users WHERE username=?',(body.username.strip(),)).fetchone()
    if not u or not u['active'] or not ph.verify(body.password,u['password_hash']): raise HTTPException(401,'Incorrect username or password')
    if body.role is not None and u['role'] != body.role: raise HTTPException(403,'This account cannot access the selected login. Choose the correct Admin or Worker login.')
    token=jwt.encode({'sub':str(u['id']),'exp':datetime.now(timezone.utc)+timedelta(hours=12)},SECRET,algorithm=ALGORITHM)
    return {'token':token,'user':user_public(u)}
@app.get('/api/auth/me')
def me(u=Depends(current)): return user_public(u)

@app.get('/api/users')
def users(u=Depends(admin)):
    with connection() as db: return [user_public(x) for x in db.execute('SELECT * FROM users ORDER BY role, id').fetchall()]
@app.post('/api/users',status_code=201)
def create_user(body:UserCreate,u=Depends(admin)):
    with tx() as db:
        try: c=db.execute('INSERT INTO users(name,username,password_hash,role,created_at) VALUES(?,?,?,?,?)',(body.name,body.username,ph.hash(body.password),body.role,now()))
        except sqlite3.IntegrityError: raise HTTPException(409,'Username already exists')
        db.execute('UPDATE users SET email=?,phone=? WHERE id=?',(body.email,body.phone,c.lastrowid))
        audit(db,u['id'],'create_user',str(c.lastrowid))
        return {'id':c.lastrowid}
@app.patch('/api/users/{uid}')
def edit_user(uid:int,body:UserPatch,u=Depends(admin)):
    with tx() as db:
        target=db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        if not target: raise HTTPException(404,'User not found')
        changes=body.model_dump(exclude_unset=True)
        if 'password' in changes:
            if not changes['password'] or len(changes['password'])<8: raise HTTPException(400,'Password needs at least 8 characters')
            changes['password_hash']=ph.hash(changes.pop('password'))
        if changes.get('active') is False and uid==u['id']: raise HTTPException(400,'Cannot deactivate your own account')
        if changes.get('active') is False and target['role']=='admin':
            count=db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
            if count<=1: raise HTTPException(400,'At least one active admin required')
        for key,val in changes.items(): db.execute(f'UPDATE users SET {key}=? WHERE id=?',(val,uid))
        audit(db,u['id'],'edit_user',str(uid))
    return {'ok':True}

@app.get('/api/sarees')
def sarees(u=Depends(current)):
    with connection() as db:
        return [dict(r) for r in db.execute("""SELECT s.*, COALESCE(SUM(CASE WHEN e.kind='collected' THEN e.quantity ELSE 0 END),0) collected, COALESCE(SUM(CASE WHEN e.kind='sold' THEN e.quantity ELSE 0 END),0) sold, COALESCE(SUM(CASE WHEN e.kind='collected' THEN e.quantity ELSE -e.quantity END),0) remaining FROM sarees s LEFT JOIN entries e ON e.saree_id=s.id GROUP BY s.id ORDER BY s.id DESC""")]
@app.post('/api/sarees',status_code=201)
def add_saree(body:SareeCreate,u=Depends(current)):
    with tx() as db:
        try: c=db.execute('INSERT INTO sarees(name,sku,category,price,created_at) VALUES(?,?,?,?,?)',(body.name,body.sku,body.category,body.price,now()))
        except sqlite3.IntegrityError: raise HTTPException(409,'SKU already exists')
        audit(db,u['id'],'create_saree',str(c.lastrowid))
    return {'id':c.lastrowid}
class CollectionCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    sku: str = Field(min_length=2, max_length=40)
    category: str = Field(default='', max_length=80)
    price: float = Field(ge=0)
    quantity: int = Field(gt=0)
    maker_id: int
    worker_id: int | None = None

@app.post('/api/saree-collections', status_code=201)
def create_saree_collection(body: CollectionCreate, u=Depends(current)):
    """Atomically create a named saree design and its first stock collection."""
    with tx() as db:
        maker = db.execute('SELECT * FROM makers WHERE id=? AND active=1', (body.maker_id,)).fetchone()
        if not maker:
            raise HTTPException(400, 'Choose an active registered maker')
        if u['role'] == 'worker':
            worker_id = u['id']
        else:
            worker_id = body.worker_id
            if worker_id is None:
                raise HTTPException(400, 'Choose a worker for this collection')
            worker = db.execute("SELECT id FROM users WHERE id=? AND role='worker' AND active=1", (worker_id,)).fetchone()
            if not worker:
                raise HTTPException(400, 'Choose an active worker account')
        try:
            cur = db.execute('INSERT INTO sarees(name,sku,category,price,created_at) VALUES(?,?,?,?,?)',
                             (body.name.strip(),body.sku.strip(),body.category.strip(),body.price,now()))
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'This product code already exists; choose a different SKU')
        saree_id = cur.lastrowid
        entry = db.execute('INSERT INTO entries(saree_id,worker_id,kind,quantity,amount,maker_name,notes,created_at) VALUES(?,?,?,?,?,?,?,?)',
                           (saree_id,worker_id,'collected',body.quantity,0,maker['name'],'Initial collection from maker '+maker['code'],now()))
        audit(db,u['id'],'create_saree_collection',str(saree_id))
        return {'saree_id':saree_id,'entry_id':entry.lastrowid,'remaining':body.quantity}

@app.patch('/api/sarees/{sid}')
def edit_saree(sid:int,body:SareePatch,u=Depends(admin)):
    changes=body.model_dump(exclude_unset=True)
    with tx() as db:
        if not db.execute('SELECT 1 FROM sarees WHERE id=?',(sid,)).fetchone(): raise HTTPException(404,'Saree not found')
        try:
            for k,v in changes.items(): db.execute(f'UPDATE sarees SET {k}=? WHERE id=?',(v,sid))
        except sqlite3.IntegrityError: raise HTTPException(409,'SKU already exists')
        audit(db,u['id'],'edit_saree',str(sid))
    return {'ok':True}

ENTRY_QUERY="""SELECT e.*,s.name saree_name,s.sku,u.name worker_name FROM entries e JOIN sarees s ON s.id=e.saree_id JOIN users u ON u.id=e.worker_id"""
@app.get('/api/entries')
def entries(u=Depends(current)):
    with connection() as db:
        if u['role']=='admin': rows=db.execute(ENTRY_QUERY+' ORDER BY e.id DESC LIMIT 2000').fetchall()
        else: rows=db.execute(ENTRY_QUERY+' WHERE e.worker_id=? ORDER BY e.id DESC LIMIT 2000',(u['id'],)).fetchall()
    return [dict(x) for x in rows]
@app.post('/api/entries',status_code=201)
def add_entry(body:EntryCreate,u=Depends(current)):
    if body.kind == 'sold': raise HTTPException(410, 'Sales and payments have been removed')
    data=body.model_dump();data['worker_id']=u['id'] if u['role']=='worker' else (data['worker_id'] or u['id'])
    if u['role']=='admin' and data['worker_id']==u['id']: raise HTTPException(400,'Choose a worker for this entry')
    with tx() as db:
        check_entry(db,data)
        c=db.execute("""INSERT INTO entries(saree_id,worker_id,kind,quantity,amount,payment_method,transaction_id,maker_name,notes,created_at) VALUES(:saree_id,:worker_id,:kind,:quantity,:amount,:payment_method,:transaction_id,:maker_name,:notes,:created_at)""",{**data,'created_at':now()})
        audit(db,u['id'],'create_entry',str(c.lastrowid))
    return {'id':c.lastrowid}
@app.patch('/api/entries/{eid}')
def edit_entry(eid:int,body:EntryPatch,u=Depends(current)):
    with tx() as db:
        old=db.execute('SELECT * FROM entries WHERE id=?',(eid,)).fetchone()
        if not old: raise HTTPException(404,'Entry not found')
        if old['kind'] == 'sold' or body.kind == 'sold': raise HTTPException(410, 'Sales and payments have been removed')
        if u['role']=='worker':
            if old['worker_id']!=u['id'] or old['created_at'][:10]!=now()[:10]:
                raise HTTPException(403,'Workers may edit only their own records from today (UTC)')
            if old['kind']=='collected' and (old['notes'] or '').startswith('Maker delivery #'):
                raise HTTPException(400,'Edit this collection through its maker delivery instead')
            if any(k in body.model_dump(exclude_unset=True) for k in ('worker_id','kind')):
                raise HTTPException(403,'Workers cannot change record owner or type')
        elif old['kind']=='collected' and (old['notes'] or '').startswith('Maker delivery #'):
            raise HTTPException(400,'Edit this collection through its maker delivery instead')
        data=dict(old);data.update(body.model_dump(exclude_unset=True))
        check_entry(db,data,eid)
        for k in ('saree_id','worker_id','kind','quantity','amount','payment_method','transaction_id','maker_name','notes'):
            db.execute(f'UPDATE entries SET {k}=? WHERE id=?',(data[k],eid))
        validate_stock(db)
        audit(db,u['id'],'edit_entry',str(eid))
    return {'ok':True}
@app.delete('/api/entries/{eid}')
def delete_entry(eid:int,u=Depends(admin)):
    with tx() as db:
        if not db.execute('SELECT 1 FROM entries WHERE id=?',(eid,)).fetchone(): raise HTTPException(404,'Entry not found')
        linked=db.execute('SELECT notes FROM entries WHERE id=?',(eid,)).fetchone()
        if linked and (linked['notes'] or '').startswith('Maker delivery #'):
            raise HTTPException(400,'Maker delivery collections cannot be deleted independently')
        db.execute('DELETE FROM entries WHERE id=?',(eid,))
        validate_stock(db)
        audit(db,u['id'],'delete_entry',str(eid))
    return {'ok':True}
@app.get('/api/dashboard')
def dashboard(u=Depends(current)):
    with connection() as db:
        where='' if u['role']=='admin' else ' WHERE worker_id=?'
        args=[] if u['role']=='admin' else [u['id']]
        r=db.execute("""SELECT COALESCE(SUM(CASE WHEN kind='collected' THEN quantity ELSE 0 END),0) collected, COALESCE(SUM(CASE WHEN kind='sold' THEN quantity ELSE 0 END),0) sold, COALESCE(SUM(CASE WHEN kind='sold' THEN amount ELSE 0 END),0) revenue, COUNT(CASE WHEN kind='sold' THEN 1 END) sales_count FROM entries"""+where,args).fetchone()
        summary=dict(r);summary['remaining']=summary['collected']-summary['sold']
        summary['by_payment']=[dict(x) for x in db.execute("SELECT payment_method, SUM(amount) amount FROM entries WHERE kind='sold'"+(' AND worker_id=?' if args else '')+' GROUP BY payment_method',args)]
        summary['daily']=[dict(x) for x in db.execute("SELECT substr(created_at,1,10) day, SUM(amount) revenue FROM entries WHERE kind='sold'"+(' AND worker_id=?' if args else '')+' GROUP BY substr(created_at,1,10) ORDER BY day DESC LIMIT 14',args)][::-1]
        return summary
@app.get('/api/audit')
def audits(u=Depends(admin)):
    with connection() as db: return [dict(x) for x in db.execute('SELECT a.*,u.name actor_name FROM audit a JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200')]

# Maker purchase orders and delivery ledger. Deliveries also enter saleable stock via a collected entry.
class MakerIn(BaseModel):
    name:str=Field(min_length=2,max_length=120)
    code:str=Field(min_length=2,max_length=30)
    phone:str|None=None
    notes:str=''
    active:bool=True
class OrderIn(BaseModel):
    maker_id:int
    saree_id:int
    ordered:int=Field(gt=0)
    notes:str=''
class DeliveryIn(BaseModel):
    order_id:int
    quantity:int=Field(gt=0)
    notes:str=''
    worker_id:int|None=None

@app.get('/api/makers')
def list_makers(u=Depends(current)):
    with connection() as db:
        return [dict(r) for r in db.execute("""SELECT m.*,COALESCE(SUM(o.ordered),0) total_ordered,
        COALESCE(SUM((SELECT COALESCE(SUM(d.quantity),0) FROM maker_deliveries d WHERE d.order_id=o.id)),0) delivered
        FROM makers m LEFT JOIN maker_orders o ON o.maker_id=m.id GROUP BY m.id ORDER BY m.code""")]
@app.post('/api/makers',status_code=201)
def create_maker(body:MakerIn,u=Depends(current)):
    with tx() as db:
        try: r=db.execute('INSERT INTO makers(name,code,phone,notes,active,created_at) VALUES(?,?,?,?,?,?)',(body.name,body.code,body.phone,body.notes,int(body.active),now()))
        except sqlite3.IntegrityError: raise HTTPException(409,'Maker code already exists')
        audit(db,u['id'],'create_maker',str(r.lastrowid))
        return {'id':r.lastrowid}
@app.patch('/api/makers/{mid}')
def update_maker(mid:int,body:MakerIn,u=Depends(admin)):
    with tx() as db:
        if not db.execute('SELECT 1 FROM makers WHERE id=?',(mid,)).fetchone(): raise HTTPException(404,'Maker not found')
        try: db.execute('UPDATE makers SET name=?,code=?,phone=?,notes=?,active=? WHERE id=?',(body.name,body.code,body.phone,body.notes,int(body.active),mid))
        except sqlite3.IntegrityError: raise HTTPException(409,'Maker code already exists')
        audit(db,u['id'],'edit_maker',str(mid))
    return {'ok':True}
@app.get('/api/maker-orders')
def list_orders(u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with connection() as db:
        return [dict(r) for r in db.execute("""SELECT o.*,m.name maker_name,m.code maker_code,s.name saree_name,
        COALESCE((SELECT SUM(d.quantity) FROM maker_deliveries d WHERE d.order_id=o.id),0) delivered,
        o.ordered-COALESCE((SELECT SUM(d.quantity) FROM maker_deliveries d WHERE d.order_id=o.id),0) pending
        FROM maker_orders o JOIN makers m ON m.id=o.maker_id JOIN sarees s ON s.id=o.saree_id ORDER BY o.id DESC""")]
@app.post('/api/maker-orders',status_code=201)
def create_order(body:OrderIn,u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with tx() as db:
        if not db.execute('SELECT 1 FROM makers WHERE id=? AND active=1',(body.maker_id,)).fetchone(): raise HTTPException(400,'Select an active maker')
        if not db.execute('SELECT 1 FROM sarees WHERE id=? AND active=1',(body.saree_id,)).fetchone(): raise HTTPException(400,'Select an active saree')
        r=db.execute('INSERT INTO maker_orders(maker_id,saree_id,ordered,notes,created_at) VALUES(?,?,?,?,?)',(body.maker_id,body.saree_id,body.ordered,body.notes,now()))
        audit(db,u['id'],'create_maker_order',str(r.lastrowid))
        return {'id':r.lastrowid}
@app.get('/api/maker-deliveries')
def list_deliveries(u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with connection() as db:
        q="""SELECT d.*,m.name maker_name,s.name saree_name,us.name worker_name FROM maker_deliveries d JOIN maker_orders o ON o.id=d.order_id JOIN makers m ON m.id=o.maker_id JOIN sarees s ON s.id=o.saree_id JOIN users us ON us.id=d.worker_id"""
        if u['role']=='worker': return [dict(r) for r in db.execute(q+' WHERE d.worker_id=? ORDER BY d.id DESC LIMIT 1000',(u['id'],))]
        return [dict(r) for r in db.execute(q+' ORDER BY d.id DESC LIMIT 1000')]
@app.post('/api/maker-deliveries',status_code=201)
def create_delivery(body:DeliveryIn,u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with tx() as db:
        o=db.execute('SELECT o.*,m.name maker_name FROM maker_orders o JOIN makers m ON m.id=o.maker_id WHERE o.id=?',(body.order_id,)).fetchone()
        if not o: raise HTTPException(404,'Order not found')
        delivered=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_deliveries WHERE order_id=?',(body.order_id,)).fetchone()[0]
        if delivered+body.quantity>o['ordered']: raise HTTPException(400,f'Only {o["ordered"]-delivered} sarees pending for this order')
        worker_id=u['id'] if u['role']=='worker' else body.worker_id
        w=db.execute("SELECT id FROM users WHERE id=? AND role='worker' AND active=1",(worker_id,)).fetchone()
        if not w: raise HTTPException(400,'Choose an active worker')
        timestamp=now()
        r=db.execute('INSERT INTO maker_deliveries(order_id,worker_id,quantity,delivered_at,notes) VALUES(?,?,?,?,?)',(body.order_id,worker_id,body.quantity,timestamp,body.notes))
        db.execute("INSERT INTO entries(saree_id,worker_id,kind,quantity,amount,maker_name,notes,created_at) VALUES(?,?,'collected',?,0,?,?,?)",(o['saree_id'],worker_id,body.quantity,o['maker_name'],f'Maker delivery #{r.lastrowid}: {body.notes}',timestamp))
        audit(db,u['id'],'record_maker_delivery',str(r.lastrowid))
        return {'id':r.lastrowid}
class DeliveryPatch(BaseModel):
    quantity:int=Field(gt=0)
    notes:str|None=None

@app.patch('/api/maker-deliveries/{delivery_id}')
def edit_maker_delivery(delivery_id:int,body:DeliveryPatch,u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with tx() as db:
        old=db.execute('SELECT * FROM maker_deliveries WHERE id=?',(delivery_id,)).fetchone()
        if not old: raise HTTPException(404,'Delivery not found')
        if u['role']=='worker' and (old['worker_id']!=u['id'] or old['delivered_at'][:10]!=now()[:10]):
            raise HTTPException(403,'Workers may edit only their own deliveries from today (UTC)')
        order=db.execute('SELECT ordered FROM maker_orders WHERE id=?',(old['order_id'],)).fetchone()
        other=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_deliveries WHERE order_id=? AND id!=?',(old['order_id'],delivery_id)).fetchone()[0]
        if other+body.quantity>order['ordered']: raise HTTPException(400,'Delivery exceeds pending maker order quantity')
        linked=db.execute("SELECT id FROM entries WHERE kind='collected' AND notes LIKE ? AND worker_id=?",(f'Maker delivery #{delivery_id}:%',old['worker_id'])).fetchone()
        if not linked: raise HTTPException(409,'Linked inventory collection is missing')
        db.execute('UPDATE maker_deliveries SET quantity=?, notes=? WHERE id=?',(body.quantity,body.notes if body.notes is not None else old['notes'],delivery_id))
        db.execute('UPDATE entries SET quantity=?, notes=? WHERE id=?',(body.quantity,f'Maker delivery #{delivery_id}: {body.notes if body.notes is not None else old["notes"]}',linked['id']))
        validate_stock(db)
        audit(db,u['id'],'edit_maker_delivery',str(delivery_id))
    return {'ok':True}

@app.get('/api/maker-summary')
def maker_summary(u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with connection() as db:
        r=db.execute('SELECT COALESCE(SUM(ordered),0) ordered FROM maker_orders').fetchone()
        d=db.execute('SELECT COALESCE(SUM(quantity),0) delivered FROM maker_deliveries').fetchone()
        today_date=datetime.now(timezone.utc).date().isoformat()
        t=db.execute('SELECT COALESCE(SUM(quantity),0) quantity FROM maker_deliveries WHERE substr(delivered_at,1,10)=?',(today_date,)).fetchone()
        return {'ordered':r['ordered'],'delivered':d['delivered'],'pending':r['ordered']-d['delivered'],'today_delivered':t['quantity']}

class ChangePassword(BaseModel): current_password:str; new_password:str=Field(min_length=8)
class OtpRequest(BaseModel): username:str; channel:Literal['email','sms']='email'
class OtpReset(BaseModel): username:str; otp:str; new_password:str=Field(min_length=8)
@app.post('/api/auth/change-password')
def change_password(body:ChangePassword,u=Depends(current)):
    if not ph.verify(body.current_password,u['password_hash']): raise HTTPException(400,'Current password is incorrect')
    with tx() as db:
        db.execute('UPDATE users SET password_hash=? WHERE id=?',(ph.hash(body.new_password),u['id']))
        audit(db,u['id'],'change_password','self')
    return {'ok':True}
def send_otp(destination,channel,otp):
    if channel=='email':
        host=os.getenv('SMTP_HOST'); username=os.getenv('SMTP_USERNAME'); password=os.getenv('SMTP_PASSWORD'); sender=os.getenv('SMTP_FROM')
        if not all((host,username,password,sender)): raise HTTPException(503,'Email delivery is not configured. Contact an administrator.')
        msg=EmailMessage();msg['Subject']='SareeFlow password reset code';msg['From']=sender;msg['To']=destination;msg.set_content(f'Your SareeFlow verification code is {otp}. It expires in 5 minutes.')
        with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context());smtp.login(username,password);smtp.send_message(msg)
    else:
        sid=os.getenv('TWILIO_ACCOUNT_SID'); token=os.getenv('TWILIO_AUTH_TOKEN'); sender=os.getenv('TWILIO_FROM')
        if not all((sid,token,sender)): raise HTTPException(503,'SMS delivery is not configured. Contact an administrator.')
        data=urllib.parse.urlencode({'From':sender,'To':destination,'Body':f'SareeFlow reset code: {otp}. Expires in 5 minutes.'}).encode()
        req=urllib.request.Request(f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json',data=data)
        req.add_header('Authorization','Basic '+base64.b64encode(f'{sid}:{token}'.encode()).decode())
        urllib.request.urlopen(req,timeout=10).close()
@app.post('/api/auth/request-otp')
def request_otp(body:OtpRequest):
    generic={'message':'If the account and verified contact exist, a code has been sent.'}
    with connection() as db: u=db.execute('SELECT * FROM users WHERE username=? AND active=1',(body.username.strip(),)).fetchone()
    if not u or not u['email' if body.channel=='email' else 'phone']: return generic
    with tx() as db:
        recent=db.execute('SELECT created_at FROM password_otps WHERE user_id=? ORDER BY id DESC LIMIT 1',(u['id'],)).fetchone()
        if recent and datetime.fromisoformat(recent['created_at'])>datetime.now(timezone.utc)-timedelta(seconds=60): raise HTTPException(429,'Please wait one minute before requesting another code')
        code=f'{secrets.randbelow(1000000):06d}'
        digest=hashlib.sha256((SECRET+str(u['id'])+code).encode()).hexdigest()
        db.execute('DELETE FROM password_otps WHERE user_id=?',(u['id'],))
        db.execute('INSERT INTO password_otps(user_id,digest,expires_at,created_at) VALUES(?,?,?,?)',(u['id'],digest,(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),now()))
    try: send_otp(u['email' if body.channel=='email' else 'phone'],body.channel,code)
    except Exception:
        with tx() as db: db.execute('DELETE FROM password_otps WHERE user_id=?',(u['id'],))
        raise HTTPException(503,'OTP delivery failed or is not configured')
    return generic
@app.post('/api/auth/reset-password')
def reset_password(body:OtpReset):
    with tx() as db:
        u=db.execute('SELECT * FROM users WHERE username=? AND active=1',(body.username.strip(),)).fetchone()
        if not u: raise HTTPException(400,'Invalid or expired code')
        otp=db.execute('SELECT * FROM password_otps WHERE user_id=? ORDER BY id DESC LIMIT 1',(u['id'],)).fetchone()
        if not otp or otp['attempts']>=5 or datetime.fromisoformat(otp['expires_at'])<datetime.now(timezone.utc): raise HTTPException(400,'Invalid or expired code')
        db.execute('UPDATE password_otps SET attempts=attempts+1 WHERE id=?',(otp['id'],))
        digest=hashlib.sha256((SECRET+str(u['id'])+body.otp).encode()).hexdigest()
        if not secrets.compare_digest(digest,otp['digest']): raise HTTPException(400,'Invalid or expired code')
        db.execute('UPDATE users SET password_hash=? WHERE id=?',(ph.hash(body.new_password),u['id']))
        db.execute('DELETE FROM password_otps WHERE user_id=?',(u['id'],))
        audit(db,u['id'],'reset_password','otp')
    return {'ok':True}


# Independent maker daily tracker. This ledger does NOT add inventory entries automatically,
# avoiding double-counting if the same sarees are also registered in Collections.
from zoneinfo import ZoneInfo

def india_today(): return datetime.now(ZoneInfo('Asia/Kolkata')).date().isoformat()

class MakerTarget(BaseModel):
    expected_total:int=Field(ge=0)

class DailyReceipt(BaseModel):
    maker_id:int
    saree_name:str=Field(min_length=2,max_length=120)
    quantity:int=Field(gt=0)
    received_date:str|None=None
    notes:str=''

@app.get('/api/maker-daily')
def maker_daily(u=Depends(current)):
    with connection() as db:
        rows=db.execute("""SELECT m.id maker_id,m.name maker_name,m.code,COALESCE(t.expected_total,0) expected_total,
          COALESCE((SELECT SUM(r.quantity) FROM maker_daily_receipts r WHERE r.maker_id=m.id),0) received_total,
          COALESCE((SELECT SUM(r.quantity) FROM maker_daily_receipts r WHERE r.maker_id=m.id AND r.received_date=?),0) today_received
          FROM makers m LEFT JOIN maker_daily_targets t ON t.maker_id=m.id ORDER BY m.code""",(india_today(),)).fetchall()
        records=db.execute("""SELECT r.*,m.name maker_name,u.name worker_name FROM maker_daily_receipts r
          JOIN makers m ON m.id=r.maker_id JOIN users u ON u.id=r.worker_id
          ORDER BY r.received_date DESC,r.id DESC LIMIT 1000""").fetchall()
    return {'today':india_today(),'makers':[dict(x)|{'remaining':max(0,x['expected_total']-x['received_total'])} for x in rows],
            'records':[dict(x) for x in records]}

@app.put('/api/maker-daily/targets/{maker_id}')
def set_maker_target(maker_id:int,body:MakerTarget,u=Depends(current)):
    with tx() as db:
        if not db.execute('SELECT 1 FROM makers WHERE id=?',(maker_id,)).fetchone(): raise HTTPException(404,'Maker not found')
        received=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_daily_receipts WHERE maker_id=?',(maker_id,)).fetchone()[0]
        if body.expected_total<received: raise HTTPException(400,'Expected total cannot be less than already received sarees')
        db.execute('INSERT INTO maker_daily_targets(maker_id,expected_total,updated_at) VALUES(?,?,?) ON CONFLICT(maker_id) DO UPDATE SET expected_total=excluded.expected_total,updated_at=excluded.updated_at',(maker_id,body.expected_total,now()))
        audit(db,u['id'],'update_maker_expected',str(maker_id))
    return {'ok':True}

@app.post('/api/maker-daily/receipts',status_code=201)
def add_daily_receipt(body:DailyReceipt,u=Depends(current)):
    day=body.received_date or india_today()
    if u['role']!='admin' and day!=india_today(): raise HTTPException(403,'Workers can add only today’s receipts')
    try: datetime.strptime(day,'%Y-%m-%d')
    except ValueError: raise HTTPException(400,'Invalid date')
    with tx() as db:
        maker=db.execute('SELECT active FROM makers WHERE id=?',(body.maker_id,)).fetchone()
        if not maker or not maker['active']: raise HTTPException(400,'Select an active maker')
        expected=db.execute('SELECT expected_total FROM maker_daily_targets WHERE maker_id=?',(body.maker_id,)).fetchone()
        received=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_daily_receipts WHERE maker_id=?',(body.maker_id,)).fetchone()[0]
        if not expected or expected['expected_total']<received+body.quantity: raise HTTPException(400,'Set/increase expected total before receiving these sarees')
        r=db.execute('INSERT INTO maker_daily_receipts(maker_id,worker_id,saree_name,quantity,received_date,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
          (body.maker_id,u['id'],body.saree_name.strip(),body.quantity,day,body.notes,now(),now()))
        audit(db,u['id'],'add_maker_daily_receipt',str(r.lastrowid))
    return {'id':r.lastrowid}

@app.put('/api/maker-daily/receipts/{receipt_id}')
def update_daily_receipt(receipt_id:int,body:DailyReceipt,u=Depends(current)):
    with tx() as db:
        old=db.execute('SELECT * FROM maker_daily_receipts WHERE id=?',(receipt_id,)).fetchone()
        if not old: raise HTTPException(404,'Receipt not found')
        if u['role']!='admin' and (old['worker_id']!=u['id'] or old['received_date']!=india_today()): raise HTTPException(403,'Workers can edit only their own receipts from today')
        day=body.received_date or old['received_date']
        try: datetime.strptime(day,'%Y-%m-%d')
        except ValueError: raise HTTPException(400,'Invalid date')
        if u['role']!='admin' and day!=india_today(): raise HTTPException(403,'Workers cannot change receipt date')
        if not db.execute('SELECT 1 FROM makers WHERE id=?',(body.maker_id,)).fetchone(): raise HTTPException(404,'Maker not found')
        expected=db.execute('SELECT expected_total FROM maker_daily_targets WHERE maker_id=?',(body.maker_id,)).fetchone()
        received=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_daily_receipts WHERE maker_id=? AND id<>?',(body.maker_id,receipt_id)).fetchone()[0]
        if not expected or expected['expected_total']<received+body.quantity: raise HTTPException(400,'Received quantity exceeds expected total')
        db.execute('UPDATE maker_daily_receipts SET maker_id=?,saree_name=?,quantity=?,received_date=?,notes=?,updated_at=? WHERE id=?',
          (body.maker_id,body.saree_name.strip(),body.quantity,day,body.notes,now(),receipt_id))
        audit(db,u['id'],'edit_maker_daily_receipt',str(receipt_id))
    return {'ok':True}
