const http=require('http');
const crypto=require('crypto');
const {Pool}=require('pg');

const PORT=process.env.PORT||3000;
const DATABASE_URL=process.env.DATABASE_URL;
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'';
const SESSION_SECRET=process.env.SESSION_SECRET||'';
const ALLOWED_ORIGIN=process.env.ALLOWED_ORIGIN||'*';

if(!DATABASE_URL) throw new Error('DATABASE_URL is required');

const pool=new Pool({connectionString:DATABASE_URL,ssl:{rejectUnauthorized:false}});
const rate=new Map();

function cors(req){
  const origin=req.headers.origin||'';
  if(ALLOWED_ORIGIN==='*') return '*';
  const allowed=ALLOWED_ORIGIN.split(',').map(s=>s.trim()).filter(Boolean);
  return allowed.includes(origin)?origin:allowed[0]||'null';
}
function send(req,res,status,data){
  res.writeHead(status,{
    'Content-Type':'application/json; charset=utf-8',
    'Access-Control-Allow-Origin':cors(req),
    'Access-Control-Allow-Headers':'Content-Type, Authorization',
    'Access-Control-Allow-Methods':'GET,POST,PATCH,OPTIONS',
    'Vary':'Origin',
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Referrer-Policy':'strict-origin-when-cross-origin'
  });
  res.end(JSON.stringify(data));
}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>25000){reject(new Error('Payload too large'));req.destroy();}});req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch{reject(new Error('Invalid JSON'))}})})}
function clean(v,n=200){return String(v??'').trim().slice(0,n)}
function validEmail(v){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)}
function publicId(prefix){return prefix+'-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase()}
function limited(req){const key=req.socket.remoteAddress||'unknown',now=Date.now(),arr=(rate.get(key)||[]).filter(t=>now-t<60000);arr.push(now);rate.set(key,arr);return arr.length>40}
function signToken(){const payload=Buffer.from(JSON.stringify({exp:Date.now()+8*3600000})).toString('base64url');const sig=crypto.createHmac('sha256',SESSION_SECRET).update(payload).digest('base64url');return payload+'.'+sig}
function auth(req){if(!SESSION_SECRET)return false;const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return false;try{const [p,s]=h.slice(7).split('.');const e=crypto.createHmac('sha256',SESSION_SECRET).update(p).digest('base64url');if(s.length!==e.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return false;return JSON.parse(Buffer.from(p,'base64url').toString()).exp>Date.now()}catch{return false}}

const server=http.createServer(async(req,res)=>{
  if(req.method==='OPTIONS') return send(req,res,204,{});
  if(limited(req)) return send(req,res,429,{error:'Too many requests'});
  const u=new URL(req.url,'http://localhost');
  try{
    if(req.method==='GET'&&u.pathname==='/api/health'){
      await pool.query('select 1');
      return send(req,res,200,{ok:true,service:'phoenix-backend',database:'connected'});
    }
    if(req.method==='GET'&&u.pathname==='/api/telemetry'){
      const m=Math.floor(Date.now()/60000),h=crypto.createHash('sha256').update(String(m)).digest();
      return send(req,res,200,{connectedUnits:12480+h[0]%180,uptime:(99.90+(h[1]%9)/100).toFixed(2),avgRange:312+h[2]%29,energyHealth:91+h[3]%8});
    }
    if(req.method==='POST'&&u.pathname==='/api/inquiries'){
      const b=await body(req),name=clean(b.name,80),email=clean(b.email,120),message=clean(b.message,1500),topic=clean(b.topic,80)||'General';
      if(!name||!validEmail(email)||!message)return send(req,res,400,{error:'Name, valid email and message are required'});
      const id=publicId('INQ');
      await pool.query('insert into inquiries(public_id,name,email,phone,topic,message) values($1,$2,$3,$4,$5,$6)',[id,name,email,clean(b.phone,24),topic,message]);
      return send(req,res,201,{ok:true,id});
    }
    if(req.method==='POST'&&u.pathname==='/api/test-drives'){
      const b=await body(req),name=clean(b.name,80),email=clean(b.email,120),phone=clean(b.phone,24),vehicle=clean(b.vehicle,80),city=clean(b.city,80),date=clean(b.preferredDate,30);
      if(!name||!validEmail(email)||!phone||!vehicle||!city||!date)return send(req,res,400,{error:'Complete all required fields'});
      const id=publicId('DRV');
      await pool.query('insert into test_drives(public_id,name,email,phone,vehicle,city,preferred_date) values($1,$2,$3,$4,$5,$6,$7)',[id,name,email,phone,vehicle,city,date]);
      return send(req,res,201,{ok:true,id});
    }
    if(req.method==='POST'&&u.pathname==='/api/admin/login'){
      const b=await body(req),a=Buffer.from(String(b.password||'')),c=Buffer.from(ADMIN_PASSWORD);
      if(!ADMIN_PASSWORD||a.length!==c.length||!crypto.timingSafeEqual(a,c))return send(req,res,401,{error:'Invalid password'});
      return send(req,res,200,{token:signToken()});
    }
    if(req.method==='GET'&&u.pathname==='/api/admin/requests'){
      if(!auth(req))return send(req,res,401,{error:'Unauthorized'});
      const [a,b]=await Promise.all([
        pool.query("select public_id as id,'inquiry' as type,name,email,phone,topic,message,status,created_at as \"createdAt\" from inquiries order by created_at desc"),
        pool.query("select public_id as id,'test-drive' as type,name,email,phone,vehicle,city,preferred_date as \"preferredDate\",status,created_at as \"createdAt\" from test_drives order by created_at desc")
      ]);
      return send(req,res,200,{items:[...a.rows,...b.rows].sort((x,y)=>new Date(y.createdAt)-new Date(x.createdAt))});
    }
    if(req.method==='PATCH'&&u.pathname.startsWith('/api/admin/requests/')){
      if(!auth(req))return send(req,res,401,{error:'Unauthorized'});
      const b=await body(req),status=clean(b.status,20),id=decodeURIComponent(u.pathname.split('/').pop());
      if(!['new','contacted','closed'].includes(status))return send(req,res,400,{error:'Invalid status'});
      const table=id.startsWith('INQ-')?'inquiries':id.startsWith('DRV-')?'test_drives':null;
      if(!table)return send(req,res,404,{error:'Request not found'});
      const r=await pool.query('update '+table+' set status=$1,updated_at=now() where public_id=$2 returning public_id',[status,id]);
      if(!r.rowCount)return send(req,res,404,{error:'Request not found'});
      return send(req,res,200,{ok:true});
    }
    return send(req,res,404,{error:'Not found'});
  }catch(e){
    console.error(e);
    return send(req,res,500,{error:'Server error'});
  }
});
server.listen(PORT,'0.0.0.0',()=>console.log('PHOENIX backend listening on',PORT));