const express=require("express"),Database=require("better-sqlite3"),crypto=require("crypto"),path=require("path");
const app=express(),PORT=process.env.PORT||3000,db=new Database(path.join(__dirname,"yoklama.db"));

app.use(express.json({limit:"5mb"}));
app.use(express.static(__dirname));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 salt TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions(
 token TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS user_data(
 user_id INTEGER PRIMARY KEY,
 marks_json TEXT NOT NULL DEFAULT '{}',
 courses_json TEXT NOT NULL DEFAULT '[]',
 updated_at TEXT NOT NULL,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function hash(p,s){
  return crypto.scryptSync(p,s,64).toString("hex")
}

function make(p){
  const s=crypto.randomBytes(16).toString("hex");
  return {salt:s,hash:hash(p,s)}
}

function check(p,u){
  const a=Buffer.from(hash(p,u.salt),"hex"),
        b=Buffer.from(u.password_hash,"hex");
  return a.length===b.length&&crypto.timingSafeEqual(a,b)
}

function createUser(username,password,role){
  const p=make(password),
        n=new Date().toISOString(),
        r=db.prepare(
          "INSERT INTO users(username,password_hash,salt,role,created_at) VALUES(?,?,?,?,?)"
        ).run(username,p.hash,p.salt,role||"user",n);

  db.prepare("INSERT INTO user_data VALUES(?,?,?,?)")
    .run(r.lastInsertRowid,"{}","[]",n);

  return r.lastInsertRowid
}

if(!db.prepare("SELECT id FROM users LIMIT 1").get()){
  createUser(
    "HAN01",
    process.env.ADMIN_PASSWORD||"HAN12345",
    "admin"
  );
}

function auth(req,res,next){
  const h=req.headers.authorization||"",
        t=h.startsWith("Bearer ")?h.slice(7):"",
        u=db.prepare(`
          SELECT u.*,s.expires_at
          FROM sessions s
          JOIN users u ON u.id=s.user_id
          WHERE s.token=?
        `).get(t);

  if(!u||!u.active||u.expires_at<Date.now()){
    return res.status(401).json({error:"unauthorized"});
  }

  req.user=u;
  req.token=t;
  next();
}

function admin(req,res,next){
  if(req.user.role!=="admin"){
    return res.status(403).json({error:"admin_only"});
  }
  next();
}

app.get("/api/health",(q,s)=>{
  s.json({ok:true});
});

app.post("/api/login",(q,s)=>{
  const n=String(q.body?.username||"").trim(),
        p=String(q.body?.password||""),
        u=db.prepare("SELECT * FROM users WHERE username=?").get(n);

  if(!u||!u.active||!check(p,u)){
    return s.status(401).json({error:"invalid_login"});
  }

  const t=crypto.randomBytes(32).toString("hex");

  db.prepare("INSERT INTO sessions VALUES(?,?,?)")
    .run(t,u.id,Date.now()+2592000000);

  s.json({
    token:t,
    userId:u.id,
    username:u.username,
    role:u.role
  });
});

app.post("/api/logout",auth,(q,s)=>{
  db.prepare("DELETE FROM sessions WHERE token=?").run(q.token);
  s.json({ok:true});
});

app.get("/api/sync",auth,(q,s)=>{
  let d=db.prepare(`
    SELECT marks_json,courses_json,updated_at
    FROM user_data
    WHERE user_id=?
  `).get(q.user.id);

  if(!d){
    const n=new Date().toISOString();

    db.prepare("INSERT INTO user_data VALUES(?,?,?,?)")
      .run(q.user.id,"{}","[]",n);

    d={
      marks_json:"{}",
      courses_json:"[]",
      updated_at:n
    };
  }

  s.json({
    marks:JSON.parse(d.marks_json),
    courses:JSON.parse(d.courses_json),
    updatedAt:d.updated_at
  });
});

app.post("/api/sync",auth,(q,s)=>{
  const m=q.body?.marks&&typeof q.body.marks==="object"
      ?q.body.marks:{};

  const c=Array.isArray(q.body?.courses)
      ?q.body.courses:[];

  const n=new Date().toISOString();

  db.prepare(`
    INSERT INTO user_data
    VALUES(?,?,?,?)
    ON CONFLICT(user_id)
    DO UPDATE SET
      marks_json=excluded.marks_json,
      courses_json=excluded.courses_json,
      updated_at=excluded.updated_at
  `).run(
    q.user.id,
    JSON.stringify(m),
    JSON.stringify(c),
    n
  );

  s.json({
    ok:true,
    updatedAt:n
  });
});

app.get("/api/users",auth,admin,(q,s)=>{
  s.json(
    db.prepare(`
      SELECT id,username,role,active,created_at
      FROM users
      ORDER BY username
    `).all()
  );
});

app.post("/api/users",auth,admin,(q,s)=>{
  const n=String(q.body?.username||"").trim(),
        p=String(q.body?.password||"");

  if(!n||!p){
    return s.status(400).json({error:"required"});
  }

  if(p.length<6){
    return s.status(400).json({error:"password_too_short"});
  }

  try{
    s.json({
      ok:true,
      id:createUser(
        n,
        p,
        q.body?.role==="admin"?"admin":"user"
      )
    });
  }catch(e){
    s.status(409).json({error:"username_exists"});
  }
});

app.post("/api/users/:id/password",auth,admin,(q,s)=>{
  const p=String(q.body?.password||"");

  if(p.length<6){
    return s.status(400).json({
      error:"password_too_short"
    });
  }

  const x=make(p);

  const r=db.prepare(`
    UPDATE users
    SET password_hash=?,salt=?
    WHERE id=?
  `).run(
    x.hash,
    x.salt,
    q.params.id
  );

  if(!r.changes){
    return s.status(404).json({
      error:"user_not_found"
    });
  }

  db.prepare(
    "DELETE FROM sessions WHERE user_id=?"
  ).run(q.params.id);

  s.json({ok:true});
});

app.post("/api/users/:id/active",auth,admin,(q,s)=>{
  if(
    +q.params.id===q.user.id &&
    !q.body?.active
  ){
    return s.status(400).json({
      error:"cannot_deactivate_self"
    });
  }

  const r=db.prepare(`
    UPDATE users
    SET active=?
    WHERE id=?
  `).run(
    q.body?.active?1:0,
    q.params.id
  );

  s.json({
    ok:!!r.changes
  });
});

app.delete("/api/users/:id",auth,admin,(q,s)=>{
  if(+q.params.id===q.user.id){
    return s.status(400).json({
      error:"cannot_delete_self"
    });
  }

  db.prepare(
    "DELETE FROM sessions WHERE user_id=?"
  ).run(q.params.id);

  db.prepare(
    "DELETE FROM user_data WHERE user_id=?"
  ).run(q.params.id);

  s.json({
    ok:!!db.prepare(
      "DELETE FROM users WHERE id=?"
    ).run(q.params.id).changes
  });
});

app.get("/",(q,s)=>{
  s.sendFile(
    path.join(__dirname,"index.html")
  );
});

app.listen(PORT,()=>{
  console.log(
    "Yoklama sunucusu: http://localhost:"+PORT
  );
});
