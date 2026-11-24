"""Saree Business API: role-based inventory, sales, and audit history."""
import os, re, secrets, hashlib, smtplib, ssl, urllib.request, urllib.parse, base64, json
from email.message import EmailMessage
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
import pymysql
import certifi
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
from pwdlib import PasswordHash

load_dotenv()

SECRET = os.getenv('SECRET_KEY', '')
if len(SECRET) < 32 or SECRET in ('replace-with-a-long-random-secret-at-least-32-characters', 'DEV_ONLY_CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT'):
    raise RuntimeError('Set a secure SECRET_KEY of at least 32 characters')
ALGORITHM = 'HS256'
ph = PasswordHash.recommended()
app = FastAPI(title='SareeFlow API', version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=[origin.strip().rstrip('/') for origin in os.getenv('CORS_ORIGINS','http://localhost:5173').split(',') if origin.strip()], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
security = HTTPBearer()

class Row(dict):
    def __getitem__(self, key):
        return tuple(self.values())[key] if isinstance(key, int) else super().__getitem__(key)

class Result:
    def __init__(self, cursor):
        self.lastrowid = cursor.lastrowid
        self.rows = [Row(r) for r in cursor.fetchall()] if cursor.description else []
        self.index = 0
    def fetchone(self):
        if self.index >= len(self.rows): return None
        row = self.rows[self.index]
        self.index += 1
        return row
    def fetchall(self):
        rows = self.rows[self.index:]
        self.index = len(self.rows)
        return rows
    def __iter__(self): return iter(self.fetchall())

class Database:
    def __init__(self):
        self.raw = pymysql.connect(
            host=os.environ['DB_HOST'], port=int(os.getenv('DB_PORT', '4000')),
            user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'],
            database=os.environ['DB_NAME'], charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor, autocommit=False,
            ssl_ca=certifi.where(), ssl_verify_cert=True, ssl_verify_identity=True,
            connect_timeout=15, read_timeout=30, write_timeout=30)
        with self.raw.cursor() as c:
            c.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
            c.execute("SET SESSION sql_mode = REPLACE(@@sql_mode, 'ONLY_FULL_GROUP_BY', '')")
    def execute(self, sql, args=None):
        with self.raw.cursor() as c:
            c.execute(sql, args if args else None)
            return Result(c)
    def __enter__(self): return self
    def __exit__(self, *args): self.raw.close()

def connection(): return Database()

@contextmanager
def tx():
    with connection() as db:
        try:
            db.raw.begin()
            # Serialize business writes, including stock and daily target checks.
            db.execute('SELECT id FROM app_write_lock WHERE id=1 FOR UPDATE')
            yield db
            db.raw.commit()
        except Exception:
            db.raw.rollback()
            raise

def now(): return datetime.now(timezone.utc).isoformat()
def asdict(row): return dict(row) if row else None

def initialize():
    with connection() as db:
        db.execute('CREATE TABLE IF NOT EXISTS app_write_lock (id INT PRIMARY KEY)')
        db.execute('INSERT IGNORE INTO app_write_lock(id) VALUES(1)')
        db.execute("CREATE TABLE IF NOT EXISTS users (id BIGINT PRIMARY KEY AUTO_INCREMENT, name TEXT NOT NULL, username VARCHAR(191) NOT NULL UNIQUE, password_hash TEXT NOT NULL, role VARCHAR(16) NOT NULL CHECK(role IN ('admin','worker')), active INTEGER NOT NULL DEFAULT 1, created_at VARCHAR(40) NOT NULL, email VARCHAR(320), phone VARCHAR(64))")
        db.execute("CREATE TABLE IF NOT EXISTS sarees (id BIGINT PRIMARY KEY AUTO_INCREMENT, name TEXT NOT NULL, sku VARCHAR(191) NOT NULL UNIQUE, category VARCHAR(2000) NOT NULL DEFAULT '', price DOUBLE NOT NULL CHECK(price>=0), active INTEGER NOT NULL DEFAULT 1, created_at VARCHAR(40) NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS entries (id BIGINT PRIMARY KEY AUTO_INCREMENT, saree_id BIGINT NOT NULL, worker_id BIGINT NOT NULL, kind VARCHAR(16) NOT NULL CHECK(kind IN ('collected','sold')), quantity INTEGER NOT NULL CHECK(quantity>0), amount DOUBLE NOT NULL DEFAULT 0 CHECK(amount>=0), payment_method VARCHAR(16) CHECK(payment_method IN ('cash','upi','online') OR payment_method IS NULL), transaction_id TEXT, maker_name TEXT, notes VARCHAR(2000) NOT NULL DEFAULT '', created_at VARCHAR(40) NOT NULL, FOREIGN KEY (saree_id) REFERENCES sarees(id), FOREIGN KEY (worker_id) REFERENCES users(id), INDEX idx_entries_saree (saree_id), INDEX idx_entries_worker (worker_id))")
        db.execute('CREATE TABLE IF NOT EXISTS audit (id BIGINT PRIMARY KEY AUTO_INCREMENT, actor_id BIGINT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL, created_at VARCHAR(40) NOT NULL, FOREIGN KEY (actor_id) REFERENCES users(id))')
        db.execute("CREATE TABLE IF NOT EXISTS makers (id BIGINT PRIMARY KEY AUTO_INCREMENT, name TEXT NOT NULL, code VARCHAR(191) NOT NULL UNIQUE, phone TEXT, notes VARCHAR(2000) NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at VARCHAR(40) NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS maker_orders (id BIGINT PRIMARY KEY AUTO_INCREMENT, maker_id BIGINT NOT NULL, saree_id BIGINT NOT NULL, ordered INTEGER NOT NULL CHECK(ordered>0), notes VARCHAR(2000) NOT NULL DEFAULT '', created_at VARCHAR(40) NOT NULL, FOREIGN KEY (maker_id) REFERENCES makers(id), FOREIGN KEY (saree_id) REFERENCES sarees(id))")
        db.execute("CREATE TABLE IF NOT EXISTS maker_deliveries (id BIGINT PRIMARY KEY AUTO_INCREMENT, order_id BIGINT NOT NULL, worker_id BIGINT NOT NULL, quantity INTEGER NOT NULL CHECK(quantity>0), delivered_at VARCHAR(40) NOT NULL, notes VARCHAR(2000) NOT NULL DEFAULT '', FOREIGN KEY (order_id) REFERENCES maker_orders(id), FOREIGN KEY (worker_id) REFERENCES users(id), INDEX idx_deliveries_order (order_id))")
        db.execute('CREATE TABLE IF NOT EXISTS password_otps (id BIGINT PRIMARY KEY AUTO_INCREMENT, user_id BIGINT NOT NULL, digest TEXT NOT NULL, expires_at VARCHAR(40) NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at VARCHAR(40) NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id))')
        db.execute('CREATE TABLE IF NOT EXISTS maker_daily_targets (\n          maker_id BIGINT PRIMARY KEY, expected_total INTEGER NOT NULL DEFAULT 0 CHECK(expected_total>=0), updated_at VARCHAR(40) NOT NULL, FOREIGN KEY (maker_id) REFERENCES makers(id))')
        db.execute("CREATE TABLE IF NOT EXISTS maker_daily_receipts (\n          id BIGINT PRIMARY KEY AUTO_INCREMENT, maker_id BIGINT NOT NULL, worker_id BIGINT NOT NULL,\n          saree_name TEXT NOT NULL, quantity INTEGER NOT NULL CHECK(quantity>0), received_date VARCHAR(40) NOT NULL,\n          notes VARCHAR(2000) NOT NULL DEFAULT '', created_at VARCHAR(40) NOT NULL, updated_at VARCHAR(40) NOT NULL, FOREIGN KEY (maker_id) REFERENCES makers(id), FOREIGN KEY (worker_id) REFERENCES users(id), INDEX idx_daily_maker_date (maker_id,received_date))")
        db.raw.commit()
    with tx() as db:
        if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            users=[('Admin One','admin1','admin'),('Admin Two','admin2','admin')] + [(f'Worker {i}',f'worker{i}','worker') for i in range(1,11)]
            bootstrap = os.getenv('BOOTSTRAP_PASSWORD', '')
            if len(bootstrap) < 16 or bootstrap == 'ChangeMe@123':
                raise RuntimeError('Set BOOTSTRAP_PASSWORD to a strong password of at least 16 characters for initial accounts')
            for name,username,role in users:
                db.execute('INSERT INTO users(name,username,password_hash,role,created_at) VALUES(%s,%s,%s,%s,%s)',(name,username,ph.hash(bootstrap),role,now()))
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
    with connection() as db: u=db.execute('SELECT * FROM users WHERE id=%s AND active=1',(uid,)).fetchone()
    if not u: raise HTTPException(401,'Account inactive or missing')
    return dict(u)
def admin(u=Depends(current)):
    if u['role']!='admin': raise HTTPException(403,'Admins only')
    return u

def audit(db,actor,action,details): db.execute('INSERT INTO audit(actor_id,action,details,created_at) VALUES(%s,%s,%s,%s)',(actor,action,details,now()))
def stock(db,saree_id,exclude=None):
    q="SELECT COALESCE(SUM(CASE WHEN kind='collected' THEN quantity ELSE -quantity END),0) FROM entries WHERE saree_id=%s"
    args=[saree_id]
    if exclude is not None: q+=' AND id<>%s';args.append(exclude)
    return db.execute(q,args).fetchone()[0]
def check_entry(db,data,exclude=None):
    saree=db.execute('SELECT * FROM sarees WHERE id=%s',(data['saree_id'],)).fetchone()
    if not saree: raise HTTPException(404,'Saree not found')
    worker=db.execute('SELECT role FROM users WHERE id=%s',(data['worker_id'],)).fetchone()
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
def health():
    with connection() as db:
        db.execute('SELECT 1')
    return {'status':'ok'}
@app.post('/api/auth/login')
def login(body:Login):
    with connection() as db: u=db.execute('SELECT * FROM users WHERE username=%s',(body.username.strip(),)).fetchone()
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
        try: c=db.execute('INSERT INTO users(name,username,password_hash,role,created_at) VALUES(%s,%s,%s,%s,%s)',(body.name,body.username,ph.hash(body.password),body.role,now()))
        except pymysql.err.IntegrityError: raise HTTPException(409,'Username already exists')
        db.execute('UPDATE users SET email=%s,phone=%s WHERE id=%s',(body.email,body.phone,c.lastrowid))
        audit(db,u['id'],'create_user',str(c.lastrowid))
        return {'id':c.lastrowid}
@app.patch('/api/users/{uid}')
def edit_user(uid:int,body:UserPatch,u=Depends(admin)):
    with tx() as db:
        target=db.execute('SELECT * FROM users WHERE id=%s',(uid,)).fetchone()
        if not target: raise HTTPException(404,'User not found')
        changes=body.model_dump(exclude_unset=True)
        if 'password' in changes:
            if not changes['password'] or len(changes['password'])<8: raise HTTPException(400,'Password needs at least 8 characters')
            changes['password_hash']=ph.hash(changes.pop('password'))
        if changes.get('active') is False and uid==u['id']: raise HTTPException(400,'Cannot deactivate your own account')
        if changes.get('active') is False and target['role']=='admin':
            count=db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
            if count<=1: raise HTTPException(400,'At least one active admin required')
        for key,val in changes.items(): db.execute(f'UPDATE users SET {key}=%s WHERE id=%s',(val,uid))
        audit(db,u['id'],'edit_user',str(uid))
    return {'ok':True}

@app.get('/api/sarees')
def sarees(u=Depends(current)):
    with connection() as db:
        return [dict(r) for r in db.execute("""SELECT s.*, COALESCE(SUM(CASE WHEN e.kind='collected' THEN e.quantity ELSE 0 END),0) collected, COALESCE(SUM(CASE WHEN e.kind='sold' THEN e.quantity ELSE 0 END),0) sold, COALESCE(SUM(CASE WHEN e.kind='collected' THEN e.quantity ELSE -e.quantity END),0) remaining FROM sarees s LEFT JOIN entries e ON e.saree_id=s.id GROUP BY s.id ORDER BY s.id DESC""")]
@app.post('/api/sarees',status_code=201)
def add_saree(body:SareeCreate,u=Depends(current)):
    with tx() as db:
        try: c=db.execute('INSERT INTO sarees(name,sku,category,price,created_at) VALUES(%s,%s,%s,%s,%s)',(body.name,body.sku,body.category,body.price,now()))
        except pymysql.err.IntegrityError: raise HTTPException(409,'SKU already exists')
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
        maker = db.execute('SELECT * FROM makers WHERE id=%s AND active=1', (body.maker_id,)).fetchone()
        if not maker:
            raise HTTPException(400, 'Choose an active registered maker')
        if u['role'] == 'worker':
            worker_id = u['id']
        else:
            worker_id = body.worker_id
            if worker_id is None:
                raise HTTPException(400, 'Choose a worker for this collection')
            worker = db.execute("SELECT id FROM users WHERE id=%s AND role='worker' AND active=1", (worker_id,)).fetchone()
            if not worker:
                raise HTTPException(400, 'Choose an active worker account')
        try:
            cur = db.execute('INSERT INTO sarees(name,sku,category,price,created_at) VALUES(%s,%s,%s,%s,%s)',
                             (body.name.strip(),body.sku.strip(),body.category.strip(),body.price,now()))
        except pymysql.err.IntegrityError:
            raise HTTPException(409, 'This product code already exists; choose a different SKU')
        saree_id = cur.lastrowid
        entry = db.execute('INSERT INTO entries(saree_id,worker_id,kind,quantity,amount,maker_name,notes,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
                           (saree_id,worker_id,'collected',body.quantity,0,maker['name'],'Initial collection from maker '+maker['code'],now()))
        audit(db,u['id'],'create_saree_collection',str(saree_id))
        return {'saree_id':saree_id,'entry_id':entry.lastrowid,'remaining':body.quantity}

@app.patch('/api/sarees/{sid}')
def edit_saree(sid:int,body:SareePatch,u=Depends(admin)):
    changes=body.model_dump(exclude_unset=True)
    with tx() as db:
        if not db.execute('SELECT 1 FROM sarees WHERE id=%s',(sid,)).fetchone(): raise HTTPException(404,'Saree not found')
        try:
            for k,v in changes.items(): db.execute(f'UPDATE sarees SET {k}=%s WHERE id=%s',(v,sid))
        except pymysql.err.IntegrityError: raise HTTPException(409,'SKU already exists')
        audit(db,u['id'],'edit_saree',str(sid))
    return {'ok':True}

ENTRY_QUERY="""SELECT e.*,s.name saree_name,s.sku,u.name worker_name FROM entries e JOIN sarees s ON s.id=e.saree_id JOIN users u ON u.id=e.worker_id"""
@app.get('/api/entries')
def entries(u=Depends(current)):
    with connection() as db:
        if u['role']=='admin': rows=db.execute(ENTRY_QUERY+' ORDER BY e.id DESC LIMIT 2000').fetchall()
        else: rows=db.execute(ENTRY_QUERY+' WHERE e.worker_id=%s ORDER BY e.id DESC LIMIT 2000',(u['id'],)).fetchall()
    return [dict(x) for x in rows]
@app.post('/api/entries',status_code=201)
def add_entry(body:EntryCreate,u=Depends(current)):
    if body.kind == 'sold': raise HTTPException(410, 'Sales and payments have been removed')
    data=body.model_dump();data['worker_id']=u['id'] if u['role']=='worker' else (data['worker_id'] or u['id'])
    if u['role']=='admin' and data['worker_id']==u['id']: raise HTTPException(400,'Choose a worker for this entry')
    with tx() as db:
        check_entry(db,data)
        c=db.execute("""INSERT INTO entries(saree_id,worker_id,kind,quantity,amount,payment_method,transaction_id,maker_name,notes,created_at) VALUES(%(saree_id)s,%(worker_id)s,%(kind)s,%(quantity)s,%(amount)s,%(payment_method)s,%(transaction_id)s,%(maker_name)s,%(notes)s,%(created_at)s)""",{**data,'created_at':now()})
        audit(db,u['id'],'create_entry',str(c.lastrowid))
    return {'id':c.lastrowid}
@app.patch('/api/entries/{eid}')
def edit_entry(eid:int,body:EntryPatch,u=Depends(current)):
    with tx() as db:
        old=db.execute('SELECT * FROM entries WHERE id=%s',(eid,)).fetchone()
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
            db.execute(f'UPDATE entries SET {k}=%s WHERE id=%s',(data[k],eid))
        validate_stock(db)
        audit(db,u['id'],'edit_entry',str(eid))
    return {'ok':True}
@app.delete('/api/entries/{eid}')
def delete_entry(eid:int,u=Depends(admin)):
    with tx() as db:
        if not db.execute('SELECT 1 FROM entries WHERE id=%s',(eid,)).fetchone(): raise HTTPException(404,'Entry not found')
        linked=db.execute('SELECT notes FROM entries WHERE id=%s',(eid,)).fetchone()
        if linked and (linked['notes'] or '').startswith('Maker delivery #'):
            raise HTTPException(400,'Maker delivery collections cannot be deleted independently')
        db.execute('DELETE FROM entries WHERE id=%s',(eid,))
        validate_stock(db)
        audit(db,u['id'],'delete_entry',str(eid))
    return {'ok':True}
@app.get('/api/dashboard')
def dashboard(u=Depends(current)):
    with connection() as db:
        where='' if u['role']=='admin' else ' WHERE worker_id=%s'
        args=[] if u['role']=='admin' else [u['id']]
        r=db.execute("""SELECT COALESCE(SUM(CASE WHEN kind='collected' THEN quantity ELSE 0 END),0) collected, COALESCE(SUM(CASE WHEN kind='sold' THEN quantity ELSE 0 END),0) sold, COALESCE(SUM(CASE WHEN kind='sold' THEN amount ELSE 0 END),0) revenue, COUNT(CASE WHEN kind='sold' THEN 1 END) sales_count FROM entries"""+where,args).fetchone()
        summary=dict(r);summary['remaining']=summary['collected']-summary['sold']
        summary['by_payment']=[dict(x) for x in db.execute("SELECT payment_method, SUM(amount) amount FROM entries WHERE kind='sold'"+(' AND worker_id=%s' if args else '')+' GROUP BY payment_method',args)]
        summary['daily']=[dict(x) for x in db.execute("SELECT substr(created_at,1,10) day, SUM(amount) revenue FROM entries WHERE kind='sold'"+(' AND worker_id=%s' if args else '')+' GROUP BY substr(created_at,1,10) ORDER BY day DESC LIMIT 14',args)][::-1]
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
        try: r=db.execute('INSERT INTO makers(name,code,phone,notes,active,created_at) VALUES(%s,%s,%s,%s,%s,%s)',(body.name,body.code,body.phone,body.notes,int(body.active),now()))
        except pymysql.err.IntegrityError: raise HTTPException(409,'Maker code already exists')
        audit(db,u['id'],'create_maker',str(r.lastrowid))
        return {'id':r.lastrowid}
@app.patch('/api/makers/{mid}')
def update_maker(mid:int,body:MakerIn,u=Depends(admin)):
    with tx() as db:
        if not db.execute('SELECT 1 FROM makers WHERE id=%s',(mid,)).fetchone(): raise HTTPException(404,'Maker not found')
        try: db.execute('UPDATE makers SET name=%s,code=%s,phone=%s,notes=%s,active=%s WHERE id=%s',(body.name,body.code,body.phone,body.notes,int(body.active),mid))
        except pymysql.err.IntegrityError: raise HTTPException(409,'Maker code already exists')
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
        if not db.execute('SELECT 1 FROM makers WHERE id=%s AND active=1',(body.maker_id,)).fetchone(): raise HTTPException(400,'Select an active maker')
        if not db.execute('SELECT 1 FROM sarees WHERE id=%s AND active=1',(body.saree_id,)).fetchone(): raise HTTPException(400,'Select an active saree')
        r=db.execute('INSERT INTO maker_orders(maker_id,saree_id,ordered,notes,created_at) VALUES(%s,%s,%s,%s,%s)',(body.maker_id,body.saree_id,body.ordered,body.notes,now()))
        audit(db,u['id'],'create_maker_order',str(r.lastrowid))
        return {'id':r.lastrowid}
@app.get('/api/maker-deliveries')
def list_deliveries(u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with connection() as db:
        q="""SELECT d.*,m.name maker_name,s.name saree_name,us.name worker_name FROM maker_deliveries d JOIN maker_orders o ON o.id=d.order_id JOIN makers m ON m.id=o.maker_id JOIN sarees s ON s.id=o.saree_id JOIN users us ON us.id=d.worker_id"""
        if u['role']=='worker': return [dict(r) for r in db.execute(q+' WHERE d.worker_id=%s ORDER BY d.id DESC LIMIT 1000',(u['id'],))]
        return [dict(r) for r in db.execute(q+' ORDER BY d.id DESC LIMIT 1000')]
@app.post('/api/maker-deliveries',status_code=201)
def create_delivery(body:DeliveryIn,u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with tx() as db:
        o=db.execute('SELECT o.*,m.name maker_name FROM maker_orders o JOIN makers m ON m.id=o.maker_id WHERE o.id=%s',(body.order_id,)).fetchone()
        if not o: raise HTTPException(404,'Order not found')
        delivered=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_deliveries WHERE order_id=%s',(body.order_id,)).fetchone()[0]
        if delivered+body.quantity>o['ordered']: raise HTTPException(400,f'Only {o["ordered"]-delivered} sarees pending for this order')
        worker_id=u['id'] if u['role']=='worker' else body.worker_id
        w=db.execute("SELECT id FROM users WHERE id=%s AND role='worker' AND active=1",(worker_id,)).fetchone()
        if not w: raise HTTPException(400,'Choose an active worker')
        timestamp=now()
        r=db.execute('INSERT INTO maker_deliveries(order_id,worker_id,quantity,delivered_at,notes) VALUES(%s,%s,%s,%s,%s)',(body.order_id,worker_id,body.quantity,timestamp,body.notes))
        db.execute("INSERT INTO entries(saree_id,worker_id,kind,quantity,amount,maker_name,notes,created_at) VALUES(%s,%s,'collected',%s,0,%s,%s,%s)",(o['saree_id'],worker_id,body.quantity,o['maker_name'],f'Maker delivery #{r.lastrowid}: {body.notes}',timestamp))
        audit(db,u['id'],'record_maker_delivery',str(r.lastrowid))
        return {'id':r.lastrowid}
class DeliveryPatch(BaseModel):
    quantity:int=Field(gt=0)
    notes:str|None=None

@app.patch('/api/maker-deliveries/{delivery_id}')
def edit_maker_delivery(delivery_id:int,body:DeliveryPatch,u=Depends(current)):
    raise HTTPException(410, 'Maker orders and deliveries have been removed')
    with tx() as db:
        old=db.execute('SELECT * FROM maker_deliveries WHERE id=%s',(delivery_id,)).fetchone()
        if not old: raise HTTPException(404,'Delivery not found')
        if u['role']=='worker' and (old['worker_id']!=u['id'] or old['delivered_at'][:10]!=now()[:10]):
            raise HTTPException(403,'Workers may edit only their own deliveries from today (UTC)')
        order=db.execute('SELECT ordered FROM maker_orders WHERE id=%s',(old['order_id'],)).fetchone()
        other=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_deliveries WHERE order_id=%s AND id!=%s',(old['order_id'],delivery_id)).fetchone()[0]
        if other+body.quantity>order['ordered']: raise HTTPException(400,'Delivery exceeds pending maker order quantity')
        linked=db.execute("SELECT id FROM entries WHERE kind='collected' AND notes LIKE %s AND worker_id=%s",(f'Maker delivery #{delivery_id}:%',old['worker_id'])).fetchone()
        if not linked: raise HTTPException(409,'Linked inventory collection is missing')
        db.execute('UPDATE maker_deliveries SET quantity=%s, notes=%s WHERE id=%s',(body.quantity,body.notes if body.notes is not None else old['notes'],delivery_id))
        db.execute('UPDATE entries SET quantity=%s, notes=%s WHERE id=%s',(body.quantity,f'Maker delivery #{delivery_id}: {body.notes if body.notes is not None else old["notes"]}',linked['id']))
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
        t=db.execute('SELECT COALESCE(SUM(quantity),0) quantity FROM maker_deliveries WHERE substr(delivered_at,1,10)=%s',(today_date,)).fetchone()
        return {'ordered':r['ordered'],'delivered':d['delivered'],'pending':r['ordered']-d['delivered'],'today_delivered':t['quantity']}

class ChangePassword(BaseModel): current_password:str; new_password:str=Field(min_length=8)
class OtpRequest(BaseModel): username:str; channel:Literal['email','sms']='email'
class OtpReset(BaseModel): username:str; otp:str; new_password:str=Field(min_length=8)
@app.post('/api/auth/change-password')
def change_password(body:ChangePassword,u=Depends(current)):
    if not ph.verify(body.current_password,u['password_hash']): raise HTTPException(400,'Current password is incorrect')
    with tx() as db:
        db.execute('UPDATE users SET password_hash=%s WHERE id=%s',(ph.hash(body.new_password),u['id']))
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
    with connection() as db: u=db.execute('SELECT * FROM users WHERE username=%s AND active=1',(body.username.strip(),)).fetchone()
    if not u or not u['email' if body.channel=='email' else 'phone']: return generic
    with tx() as db:
        recent=db.execute('SELECT created_at FROM password_otps WHERE user_id=%s ORDER BY id DESC LIMIT 1',(u['id'],)).fetchone()
        if recent and datetime.fromisoformat(recent['created_at'])>datetime.now(timezone.utc)-timedelta(seconds=60): raise HTTPException(429,'Please wait one minute before requesting another code')
        code=f'{secrets.randbelow(1000000):06d}'
        digest=hashlib.sha256((SECRET+str(u['id'])+code).encode()).hexdigest()
        db.execute('DELETE FROM password_otps WHERE user_id=%s',(u['id'],))
        db.execute('INSERT INTO password_otps(user_id,digest,expires_at,created_at) VALUES(%s,%s,%s,%s)',(u['id'],digest,(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),now()))
    try: send_otp(u['email' if body.channel=='email' else 'phone'],body.channel,code)
    except Exception:
        with tx() as db: db.execute('DELETE FROM password_otps WHERE user_id=%s',(u['id'],))
        raise HTTPException(503,'OTP delivery failed or is not configured')
    return generic
@app.post('/api/auth/reset-password')
def reset_password(body:OtpReset):
    with tx() as db:
        u=db.execute('SELECT * FROM users WHERE username=%s AND active=1',(body.username.strip(),)).fetchone()
        if not u: raise HTTPException(400,'Invalid or expired code')
        otp=db.execute('SELECT * FROM password_otps WHERE user_id=%s ORDER BY id DESC LIMIT 1',(u['id'],)).fetchone()
        if not otp or otp['attempts']>=5 or datetime.fromisoformat(otp['expires_at'])<datetime.now(timezone.utc): raise HTTPException(400,'Invalid or expired code')
        db.execute('UPDATE password_otps SET attempts=attempts+1 WHERE id=%s',(otp['id'],))
        digest=hashlib.sha256((SECRET+str(u['id'])+body.otp).encode()).hexdigest()
        valid = secrets.compare_digest(digest,otp['digest'])
        if valid:
            db.execute('UPDATE users SET password_hash=%s WHERE id=%s',(ph.hash(body.new_password),u['id']))
            db.execute('DELETE FROM password_otps WHERE user_id=%s',(u['id'],))
            audit(db,u['id'],'reset_password','otp')
    if not valid: raise HTTPException(400,'Invalid or expired code')
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
          COALESCE((SELECT SUM(r.quantity) FROM maker_daily_receipts r WHERE r.maker_id=m.id AND r.received_date=%s),0) today_received
          FROM makers m LEFT JOIN maker_daily_targets t ON t.maker_id=m.id ORDER BY m.code""",(india_today(),)).fetchall()
        records=db.execute("""SELECT r.*,m.name maker_name,u.name worker_name FROM maker_daily_receipts r
          JOIN makers m ON m.id=r.maker_id JOIN users u ON u.id=r.worker_id
          ORDER BY r.received_date DESC,r.id DESC LIMIT 1000""").fetchall()
    return {'today':india_today(),'makers':[dict(x)|{'remaining':max(0,x['expected_total']-x['received_total'])} for x in rows],
            'records':[dict(x) for x in records]}

@app.put('/api/maker-daily/targets/{maker_id}')
def set_maker_target(maker_id:int,body:MakerTarget,u=Depends(current)):
    with tx() as db:
        if not db.execute('SELECT 1 FROM makers WHERE id=%s',(maker_id,)).fetchone(): raise HTTPException(404,'Maker not found')
        received=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_daily_receipts WHERE maker_id=%s',(maker_id,)).fetchone()[0]
        if body.expected_total<received: raise HTTPException(400,'Expected total cannot be less than already received sarees')
        db.execute('INSERT INTO maker_daily_targets(maker_id,expected_total,updated_at) VALUES(%s,%s,%s) ON DUPLICATE KEY UPDATE expected_total=VALUES(expected_total),updated_at=VALUES(updated_at)',(maker_id,body.expected_total,now()))
        audit(db,u['id'],'update_maker_expected',str(maker_id))
    return {'ok':True}

@app.post('/api/maker-daily/receipts',status_code=201)
def add_daily_receipt(body:DailyReceipt,u=Depends(current)):
    day=body.received_date or india_today()
    if u['role']!='admin' and day!=india_today(): raise HTTPException(403,'Workers can add only today’s receipts')
    try: datetime.strptime(day,'%Y-%m-%d')
    except ValueError: raise HTTPException(400,'Invalid date')
    with tx() as db:
        maker=db.execute('SELECT active FROM makers WHERE id=%s',(body.maker_id,)).fetchone()
        if not maker or not maker['active']: raise HTTPException(400,'Select an active maker')
        expected=db.execute('SELECT expected_total FROM maker_daily_targets WHERE maker_id=%s',(body.maker_id,)).fetchone()
        received=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_daily_receipts WHERE maker_id=%s',(body.maker_id,)).fetchone()[0]
        if not expected or expected['expected_total']<received+body.quantity: raise HTTPException(400,'Set/increase expected total before receiving these sarees')
        r=db.execute('INSERT INTO maker_daily_receipts(maker_id,worker_id,saree_name,quantity,received_date,notes,created_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
          (body.maker_id,u['id'],body.saree_name.strip(),body.quantity,day,body.notes,now(),now()))
        audit(db,u['id'],'add_maker_daily_receipt',str(r.lastrowid))
    return {'id':r.lastrowid}

@app.put('/api/maker-daily/receipts/{receipt_id}')
def update_daily_receipt(receipt_id:int,body:DailyReceipt,u=Depends(current)):
    with tx() as db:
        old=db.execute('SELECT * FROM maker_daily_receipts WHERE id=%s',(receipt_id,)).fetchone()
        if not old: raise HTTPException(404,'Receipt not found')
        if u['role']!='admin' and (old['worker_id']!=u['id'] or old['received_date']!=india_today()): raise HTTPException(403,'Workers can edit only their own receipts from today')
        day=body.received_date or old['received_date']
        try: datetime.strptime(day,'%Y-%m-%d')
        except ValueError: raise HTTPException(400,'Invalid date')
        if u['role']!='admin' and day!=india_today(): raise HTTPException(403,'Workers cannot change receipt date')
        if not db.execute('SELECT 1 FROM makers WHERE id=%s',(body.maker_id,)).fetchone(): raise HTTPException(404,'Maker not found')
        expected=db.execute('SELECT expected_total FROM maker_daily_targets WHERE maker_id=%s',(body.maker_id,)).fetchone()
        received=db.execute('SELECT COALESCE(SUM(quantity),0) FROM maker_daily_receipts WHERE maker_id=%s AND id<>%s',(body.maker_id,receipt_id)).fetchone()[0]
        if not expected or expected['expected_total']<received+body.quantity: raise HTTPException(400,'Received quantity exceeds expected total')
        db.execute('UPDATE maker_daily_receipts SET maker_id=%s,saree_name=%s,quantity=%s,received_date=%s,notes=%s,updated_at=%s WHERE id=%s',
          (body.maker_id,body.saree_name.strip(),body.quantity,day,body.notes,now(),receipt_id))
        audit(db,u['id'],'edit_maker_daily_receipt',str(receipt_id))
    return {'ok':True}
