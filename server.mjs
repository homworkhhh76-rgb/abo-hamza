import {createServer} from 'node:http';
import {readFileSync, createReadStream} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {createDecipheriv, createHash, createHmac, pbkdf2Sync, randomBytes, scrypt, timingSafeEqual, webcrypto} from 'node:crypto';
import {promisify} from 'node:util';

const env=process.env;
const file=name=>new URL(name,import.meta.url);
const legacy=JSON.parse(readFileSync(file('legacy-config.json')));
const context={crypto:webcrypto,structuredClone};
context.window=context;
const localPage=readFileSync(file('index.html'),'utf8');
const source=localPage.split('/* TAXI_ENGINE_START */')[1].split('/* TAXI_ENGINE_END */')[0];
runInNewContext(source,context,{filename:'taxi-engine.js'});
const engine=context.TaxiEngine;
const previewStart='/* TAXI_PREVIEW_START */';
const previewEnd='/* TAXI_PREVIEW_END */';
const previewBlockStart=localPage.indexOf(previewStart);
const previewBlockEnd=localPage.indexOf(previewEnd);
if(previewBlockStart<0||previewBlockEnd<=previewBlockStart)throw Error('Missing standalone preview block');
const hostedPage=localPage.slice(0,previewBlockStart)+localPage.slice(previewBlockEnd+previewEnd.length);
const officeId='abu-hamza-primary';
const derive=promisify(scrypt);
const digest=value=>createHash('sha256').update(value).digest('hex');
const equal=(a,b)=>timingSafeEqual(Buffer.from(digest(a),'hex'),Buffer.from(digest(b),'hex'));
const error=(status,message)=>Object.assign(new Error(message),{status});
const sessions=new Map(), failures=new Map();
const adminPassword=env.TAXI_ADMIN_PASSWORD;
const localPath=env.TAXI_LOCAL_DB;
const metaSecret=env.META_APP_SECRET;
const metaVerify=env.WHATSAPP_VERIFY_TOKEN;
const metaNumber=env.WHATSAPP_PHONE_NUMBER_ID;
if(!adminPassword||adminPassword.length>128)throw Error('TAXI_ADMIN_PASSWORD is required');
function decryptLegacy(){
 const bytes=Buffer.from(legacy.token,'base64');
 const key=pbkdf2Sync(env.TAXI_LEGACY_PASSWORD||adminPassword,Buffer.from(legacy.salt,'base64'),legacy.iterations,32,'sha256');
 const decoder=createDecipheriv('aes-256-gcm',key,Buffer.from(legacy.iv,'base64'));
 decoder.setAuthTag(bytes.subarray(-16));
 return Buffer.concat([decoder.update(bytes.subarray(0,-16)),decoder.final()]).toString();
}
const turso=env.TURSO_URL||legacy.url;
const token=localPath?'':env.TURSO_AUTH_TOKEN||decryptLegacy();
const endpoint=new URL('/v2/pipeline',turso.replace(/^libsql:/,'https:'));
if(endpoint.protocol!=='https:')throw Error('TURSO_URL must use HTTPS or libsql');
async function cloud(sql,args=[]){
 const response=await fetch(endpoint,{method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json'},
  body:JSON.stringify({requests:[{type:'execute',stmt:{sql,args:args.map(x=>({type:typeof x==='number'?'integer':'text',value:String(x)}))}},{type:'close'}]}),
  signal:AbortSignal.timeout(12000)});
 if(!response.ok)throw error(503,'قاعدة البيانات غير متاحة حاليًا');
 const {results}=await response.json();
 if(results[0]?.type!=='ok')throw error(503,'تعذّر تنفيذ العملية في قاعدة البيانات');
 const {rows,affected_row_count}=results[0].response.result;
 return {row:rows?.[0]?.map(v=>v.value),affected:+affected_row_count};
}
let sqlite;
if(localPath){
 const {DatabaseSync}=await import('node:sqlite');
 sqlite=new DatabaseSync(localPath);
 sqlite.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=3000;');
}
async function sql(statement,args=[]){
 if(!sqlite)return cloud(statement,args);
 const q=sqlite.prepare(statement);
 if(statement.startsWith('SELECT')){const row=q.get(...args);return {row:row&&Object.values(row)}}
 return {affected:q.run(...args).changes};
}
let schema;
function ensure(){
 return schema??=(async()=>{
  await sql('CREATE TABLE IF NOT EXISTS taxi_offices (id TEXT PRIMARY KEY, content TEXT NOT NULL, revision INTEGER NOT NULL, updated_at TEXT NOT NULL)');
  const office=engine.newOffice();
  await sql('INSERT OR IGNORE INTO taxi_offices(id,content,revision,updated_at) VALUES (?,?,?,?)',[officeId,JSON.stringify(office),1,new Date().toISOString()]);
 })().catch(err=>{schema=null;throw err});
}
async function load(){
 await ensure();
 const {row}=await sql('SELECT content,revision FROM taxi_offices WHERE id=?',[officeId]);
 if(!row)throw error(503,'بيانات المكتب غير متاحة حاليًا');
 const office=context.migrateTaxiOffice(JSON.parse(row[0]));
 office.revision=+row[1];
 return office;
}
async function update(change){
 for(let attempt=0;attempt<12;attempt++){
  const office=await load(),revision=office.revision;
  const result=await change(office);
  if(result.write===false)return result.value;
  office.revision=revision+1;
  const reply=await sql('UPDATE taxi_offices SET content=?,revision=?,updated_at=? WHERE id=? AND revision=?',
   [JSON.stringify(office),office.revision,new Date().toISOString(),officeId,revision]);
  if(reply.affected===1)return result.value;
  await new Promise(resolve=>setTimeout(resolve,15+Math.random()*60*(attempt+1)));
 }
 throw error(503,'قاعدة البيانات مشغولة. ستتم إعادة المحاولة تلقائيًا');
}
const username=value=>String(value||'').trim().normalize('NFKC').toLowerCase();
function principal(office,session){
 const user=session.admin?office.users.find(u=>u.active&&u.role==='admin'):
  office.users.find(u=>u.id===session.id&&u.active&&u.role==='reception'&&u.version===session.version);
 if(!user)throw error(401,'انتهت صلاحية الدخول. سجّل الدخول مرة أخرى');
 return user;
}
function adminOnly(user){
 if(user.role!=='admin')throw error(403,'هذه العملية لمدير المكتب');
}
const view=(office,user)=>({state:engine.publicView(office,user),revision:office.revision});
function send(res,status,value,type='application/json; charset=utf-8'){
 res.writeHead(status,{'content-type':type,'cache-control':'no-store','x-content-type-options':'nosniff'});
 res.end(type.startsWith('application/json')?JSON.stringify(value):String(value));
}
async function body(req,limit=5_000_000){
 const parts=[];
 let size=0;
 for await(const chunk of req){
  size+=chunk.length;
  if(size>limit)throw error(413,'حجم الطلب أكبر من الحد المسموح');
  parts.push(chunk);
 }
 return Buffer.concat(parts);
}
async function json(req,limit){
 try{return JSON.parse((await body(req,limit)).toString())}
 catch(e){throw e.status?e:error(400,'بيانات غير صالحة')}
}
function utc(value){
 const date=new Date(value);
 return Number.isFinite(+date)&&+date<=Date.now()+300000?date.toISOString():new Date().toISOString();
}
async function login(req){
 const ip=req.socket.remoteAddress;
 const bucket=failures.get(ip)||{until:Date.now()+60000,count:0};
 if(bucket.until<Date.now()){bucket.until=Date.now()+60000;bucket.count=0}
 if(bucket.count>=25)throw error(429,'محاولات دخول كثيرة. حاول بعد دقيقة');
 const input=await json(req,4096), name=username(input.username)||'admin',password=String(input.password||'');
 if(password.length>128)throw error(400,'كلمة المرور غير صالحة');
 const office=await load(),admin=name==='admin';
 const user=admin?office.users.find(u=>u.role==='admin'&&u.active):office.users.find(u=>u.username===name&&u.role==='reception'&&u.active);
 const stored=office.credentials?.[user?.id];
 const valid=admin?equal(password,adminPassword):equal((await derive(password,stored?.salt||'unused-salt',64)).toString('hex'),stored?.hash||'');
 if(!user||!valid){bucket.count++;failures.set(ip,bucket);throw error(401,'اسم المستخدم أو كلمة المرور غير صحيحة')}
 const token=randomBytes(32).toString('hex'), now=Date.now();
 for(const [key,session] of sessions)if(session.exp<now)sessions.delete(key);
 for(const [key,limit] of failures)if(limit.until<now)failures.delete(key);
 sessions.set(token,{admin,id:user.id,version:user.version,exp:now+12*60*60*1000});
 return {...view(office,user),token};
}
async function staffChange(req,session){
 const data=await json(req,16000);
 if(data.action==='branch'){
  const name=String(data.name||'').trim();
  if(!name||name.length>100)throw error(400,'تحقق من اسم الفرع');
  return update(office=>{
   adminOnly(principal(office,session));
   if(office.branches.some(b=>b.name===name))throw error(400,'اسم الفرع مسجّل مسبقًا');
   office.branches.push({id:webcrypto.randomUUID(),name});
   return {value:{ok:true}};
  });
 }
 if(data.action!=='employee')throw error(400,'العملية غير معروفة');
 const password=String(data.password||''),name=String(data.name||'').trim(),loginName=username(data.username);
 if(!name||name.length>100||!/^[-_.\p{L}\p{N}]{2,50}$/u.test(loginName)||loginName==='admin')throw error(400,'تحقق من اسم الموظف واسم المستخدم');
 if((!data.id||password)&&(password.length<8||password.length>128||equal(password,adminPassword)))throw error(400,'استخدم كلمة مرور مستقلة من ٨ أحرف على الأقل');
 const salt=password?randomBytes(16).toString('hex'):null;
 const hash=salt?(await derive(password,salt,64)).toString('hex'):null;
 return update(office=>{
  adminOnly(principal(office,session));
  if(!office.branches.some(b=>b.id===data.branchId))throw error(400,'اختر فرعًا صالحًا');
  const existing=office.users.find(u=>u.id===data.id&&u.role==='reception');
  if(data.id&&!existing)throw error(404,'الموظف غير موجود');
  if(office.users.some(u=>u.id!==existing?.id&&u.username===loginName))throw error(400,'اسم الدخول مستخدم');
  if(existing&&existing.username!==loginName)throw error(400,'اسم دخول الحساب ثابت');
  if(existing&&existing.branchId!==data.branchId)throw error(400,'أنشئ حسابًا مستقلًا للفرع الجديد ليبقى سجل الحساب القديم محفوظًا');
  const row={id:existing?.id||webcrypto.randomUUID(),username:loginName,name,role:'reception',branchId:data.branchId,active:data.active!==false,version:(existing?.version||0)+1};
  if(existing)Object.assign(existing,row);else office.users.push(row);
  office.credentials??={};
  if(hash)office.credentials[row.id]={salt,hash};
  return {value:{ok:true}};
 });
}
function tracking(office){
 office._ops=Array.isArray(office._ops)?Object.fromEntries(office._ops.map(op=>[op.id,op])):office._ops||{};
 return office._ops;
}
async function mutation(req,session){
 const op=await json(req);
 if(typeof op.id!=='string'||!/^[-_0-9a-z]{12,128}$/i.test(op.id)||typeof op.kind!=='string')throw error(400,'معرّف العملية غير صالح');
 const answer=await update(office=>{
  const user=principal(office,session), trackingRows=tracking(office);
  const previous=Object.hasOwn(trackingRows,op.id)&&trackingRows[op.id];
  if(previous){
   if(previous.actor&&previous.actor!==user.id)throw error(403,'العملية خارج الحساب');
   return {write:false,value:{...view(office,user),result:previous.result}};
  }
  let applied;
  try{applied=engine.mutate(office,op.kind,op.data,user,utc(op.createdAt))}
  catch(e){throw error(422,e.message)}
  trackingRows[op.id]={actor:user.id,result:applied.result};
  if(!applied.changed)office.revision++;
  return {value:{...view(office,user),result:applied.result}};
 });
 return answer;
}
async function whatsapp(req,url){
 if(!metaSecret||!metaVerify||!metaNumber)throw error(404,'القناة غير مفعلة');
 if(req.method==='GET'){
  const p=url.searchParams;
  if(p.get('hub.mode')!=='subscribe'||!equal(p.get('hub.verify_token')||'',metaVerify))throw error(403,'تعذّر التحقق');
  return p.get('hub.challenge')||'';
 }
 if(req.method!=='POST')throw error(405,'طريقة الطلب غير مدعومة');
 const raw=await body(req,1024*1024);
 if(!equal(req.headers['x-hub-signature-256']||'','sha256='+createHmac('sha256',metaSecret).update(raw).digest('hex')))throw error(403,'توقيع الرسالة غير صالح');
 const envelope=JSON.parse(raw.toString()),incoming=[];
 if(envelope.object!=='whatsapp_business_account')return 'OK';
 for(const entry of envelope.entry||[])for(const change of entry.changes||[]){
  const value=change.value;
  if(change.field!=='messages'||String(value?.metadata?.phone_number_id)!==metaNumber)continue;
  for(const msg of value.messages||[]){
   const phone=context.phoneInternational(msg.from);
   if(!phone||!msg.id)continue;
   const name=value.contacts?.find(c=>c.wa_id===msg.from)?.profile?.name;
   incoming.push({id:String(msg.id),phone:'+'+phone,customerName:String(name||'').slice(0,200),body:String(msg.text?.body||'').slice(0,6000),type:String(msg.type||'').slice(0,40),created:utc(Number(msg.timestamp)*1000)});
  }
 }
 if(incoming.length)await update(office=>{
  const known=new Set(office.inbox.map(r=>r.id));
  const added=incoming.filter(r=>{if(known.has(r.id))return false;known.add(r.id);return true});
  office.inbox.unshift(...added);
  return {write:added.length>0,value:null};
 });
 return 'OK';
}
const publicFiles={
 '/':['index.html','text/html; charset=utf-8'],'/index.html':['index.html','text/html; charset=utf-8'],
 '/sw.js':['sw.js','text/javascript; charset=utf-8'],'/manifest.webmanifest':['manifest.webmanifest','application/manifest+json'],
 '/icons/icon-192.png':['icons/icon-192.png','image/png'],'/icons/icon-512.png':['icons/icon-512.png','image/png']
};
const server=createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://localhost'),path=url.pathname;
  if(path==='/webhooks/whatsapp')return send(res,200,await whatsapp(req,url),'text/plain; charset=utf-8');
  const asset=Object.hasOwn(publicFiles,path)&&publicFiles[path];
  if(req.method==='GET'&&asset){
   res.writeHead(200,{'content-type':asset[1],'cache-control':'no-cache','x-content-type-options':'nosniff','referrer-policy':'no-referrer'});
   if(asset[0]==='index.html')return res.end(hostedPage);
   return createReadStream(file(asset[0])).pipe(res);
  }
  if(path==='/api/login'&&req.method==='POST')return send(res,200,await login(req));
  if(!path.startsWith('/api/'))throw error(404,'الصفحة غير موجودة');
  const key=(req.headers.authorization||'').replace(/^Bearer /,'');
  const session=sessions.get(key);
  if(!session||session.exp<Date.now())throw error(401,'سجّل الدخول مرة أخرى');
  if(path==='/api/logout'&&req.method==='POST'){sessions.delete(key);return send(res,200,{ok:true})}
  if(path==='/api/mutate'&&req.method==='POST')return send(res,200,await mutation(req,session));
  if(path==='/api/state'&&req.method==='GET'){
   const office=await load(),user=principal(office,session);
   return send(res,200,Number(url.searchParams.get('after'))===office.revision?{unchanged:true,revision:office.revision}:view(office,user));
  }
  const office=await load(),user=principal(office,session);
  adminOnly(user);
  if(path==='/api/staff'&&req.method==='POST')return send(res,200,await staffChange(req,session));
  if(path==='/api/backup'&&req.method==='GET'){
   delete office.credentials;
   for(const user of office.users)if(user.role==='reception')user.active=false;
   return send(res,200,{type:'abu-hamza-local-backup',version:1,office,checksum:digest(JSON.stringify(office)),exportedAt:new Date().toISOString()});
  }
  if((path==='/api/import'||path==='/api/wipe-cloud')&&req.method==='POST'){
   const restoring=path==='/api/import';
   const input=restoring?await json(req,30_000_000):null;
   if(restoring&&(input?.type!=='abu-hamza-local-backup'||input.version!==1||!input.office||!equal(digest(JSON.stringify(input.office)),String(input.checksum))))throw error(400,'ملف النسخة الاحتياطية غير صالح');
   const result=await update(current=>{
    const user=principal(current,session);adminOnly(user);
    const next=restoring?context.migrateTaxiOffice(engine.validateImport(input.office)):engine.newOffice();
    next.revision=current.revision+1;
    next._ops=tracking(current);
    next.credentials=current.credentials;
    if(restoring){
     const accounts=current.users.filter(u=>u.role==='reception');
     next.users=[...next.users.filter(u=>u.role!=='reception'),...accounts];
     for(const branch of current.branches)if(!next.branches.some(b=>b.id===branch.id))next.branches.push(branch);
    }
    Object.keys(current).forEach(k=>delete current[k]);Object.assign(current,next,{revision:next.revision-1});
    return {value:view(next,principal(next,session))};
   });
   return send(res,200,result);
  }
  throw error(404,'العملية غير موجودة');
 }catch(e){
  if(!e.status)console.error('Taxi request failure:',e.name);
  if(!res.headersSent)send(res,e.status||503,{error:e.status?e.message:'تعذر الاتصال بقاعدة البيانات حاليًا'});
 }
});
server.listen(Number(env.PORT)||3000,env.HOST||'0.0.0.0',()=>console.log('Abu Hamza Taxi is ready'));
