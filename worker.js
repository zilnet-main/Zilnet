const SESSION_DAYS = 30;
const RESET_MINUTES = 15;

class HttpError extends Error { constructor(status, message){ super(message); this.status=status; } }
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8', ...headers}});
const ok = (data={}) => json(data);
const fail = (status, message) => json({error:message}, status);

async function readJSON(req){
  try { return await req.json(); }
  catch { throw new HttpError(400,'Invalid JSON body'); }
}
function clean(s, max=10000){ return String(s ?? '').trim().slice(0,max); }
function usernameValid(s){ return /^[a-zA-Z0-9_.-]{3,30}$/.test(s); }
function emailValid(s){ return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }
function hex(bytes){ return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function b64(bytes){ return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function randomToken(n=32){ const a=new Uint8Array(n); crypto.getRandomValues(a); return b64(a); }

async function sha256(text){
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

async function hashPassword(password, saltB64=randomToken(16), iterations=120000){
  const salt = Uint8Array.from(
    atob(
      saltB64.replace(/-/g,'+').replace(/_/g,'/')
      .padEnd(Math.ceil(saltB64.length/4)*4,'=')
    ),
    c=>c.charCodeAt(0)
  );

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name:'PBKDF2',
      salt,
      iterations,
      hash:'SHA-256'
    },
    key,
    256
  );

  return `pbkdf2$sha256$${iterations}$${saltB64}$${b64(bits)}`;
}

async function verifyPassword(password, stored){
  const p=String(stored||'').split('$');

  if(p.length!==5 || p[0]!=='pbkdf2' || p[1]!=='sha256')
    return false;

  const iterations=Number(p[2]);

  if(
    !Number.isInteger(iterations) ||
    iterations<10000 ||
    iterations>1000000
  ) return false;

  const salt=p[3];
  const got=await hashPassword(password,salt,iterations);

  return got===stored;
}

function cookie(token, maxAge=SESSION_DAYS*86400){
  return `zilnet_session=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie(){
  return 'zilnet_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax';
}

function getCookie(req,name){
  const raw=req.headers.get('Cookie')||'';

  for(const part of raw.split(';')){
    const [k,...v]=part.trim().split('=');
    if(k===name)return v.join('=');
  }

  return '';
}

async function requireUser(req,env){
  const token=getCookie(req,'zilnet_session');

  if(!token)
    throw new HttpError(401,'Login required');

  const row=await env.DB.prepare(`
    SELECT u.*
    FROM sessions s
    JOIN users u ON u.id=s.user_id
    WHERE s.token=? AND s.expires_at>?
  `).bind(token,Date.now()).first();

  if(!row)
    throw new HttpError(401,'Session expired');

  return row;
}

function publicUser(u){
  if(!u)return null;

  return {
    id:Number(u.id),
    username:u.username,
    display_name:u.display_name||'',
    bio:u.bio||'',
    avatar_url:u.avatar_url||'',
    skills:u.skills||'',
    created_at:u.created_at||''
  };
}

function ownUser(u){
  return {
    ...publicUser(u),
    email:u.email||''
  };
}

async function userByUsername(env, username){
  return await env.DB.prepare(
    'SELECT * FROM users WHERE lower(username)=lower(?)'
  ).bind(username).first();
}

async function notify(env,{userId,actorId,type,postId=null}){
  if(Number(userId)===Number(actorId)) return;

  const settings=await env.DB.prepare(
    'SELECT notification_settings FROM user_settings WHERE user_id=?'
  ).bind(String(userId)).first();

  let ns={};

  try{
    ns=JSON.parse(settings?.notification_settings||'{}');
  }catch{}

  const map={
    like:'likes',
    comment:'comments',
    follow:'follows',
    message:'messages'
  };

  if(map[type] && ns[map[type]]===false)
    return;

  await env.DB.prepare(`
    INSERT INTO notifications
    (user_id,actor_id,type,post_id)
    VALUES (?,?,?,?)
  `).bind(
    Number(userId),
    Number(actorId),
    type,
    postId
  ).run();
}

async function profileSettings(env,userId){
  const s=await env.DB.prepare(
    'SELECT * FROM user_settings WHERE user_id=?'
  ).bind(String(userId)).first();

  if(s)
    return {
      ...s,
      notification_settings:JSON.parseSafe?{}:undefined
    };

  return {
    theme:'system',
    profile_visibility:'public',
    message_privacy:'everyone',
    notification_settings:{}
  };
}

function parseNS(v){
  try{
    return JSON.parse(v||'{}');
  }catch{
    return {};
  }
}

async function getSettings(env,userId){
  let s=await env.DB.prepare(
    'SELECT * FROM user_settings WHERE user_id=?'
  ).bind(String(userId)).first();

  if(!s){
    await env.DB.prepare(
      'INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)'
    ).bind(String(userId)).run();

    s=await env.DB.prepare(
      'SELECT * FROM user_settings WHERE user_id=?'
    ).bind(String(userId)).first();
  }

  return {
    ...s,
    notification_settings:parseNS(s.notification_settings)
  };
}

async function getPublicProfile(env,viewer,username){
  const u=await userByUsername(env,username);

  if(!u)
    throw new HttpError(404,'User not found');

  const s=await getSettings(env,u.id);

  const isOwn=
    viewer &&
    Number(viewer.id)===Number(u.id);

  const following=viewer?
    !!(await env.DB.prepare(`
      SELECT 1
      FROM follows
      WHERE follower_id=? AND following_id=?
    `).bind(
      Number(viewer.id),
      Number(u.id)
    ).first())
    :false;

  const followers=await env.DB.prepare(`
    SELECT COUNT(*) c
    FROM follows
    WHERE following_id=?
  `).bind(Number(u.id)).first();

  const followingCount=await env.DB.prepare(`
    SELECT COUNT(*) c
    FROM follows
    WHERE follower_id=?
  `).bind(Number(u.id)).first();

  if(
    s.profile_visibility==='private' &&
    !isOwn &&
    !following
  ){
    return {
      user:{
        ...publicUser(u),
        followers_count:Number(followers?.c||0),
        following_count:Number(followingCount?.c||0),
        following
      },
      posts:[],
      private:true
    };
  }

  const posts=await env.DB.prepare(`
    SELECT
      p.*,
      u.username,
      u.display_name,
      u.avatar_url,

      (SELECT COUNT(*)
       FROM likes l
       WHERE l.post_id=p.id) likes_count,

      (SELECT COUNT(*)
       FROM comments c
       WHERE c.post_id=p.id) comments_count,

      CASE
        WHEN ? IS NOT NULL
        THEN EXISTS(
          SELECT 1
          FROM likes l2
          WHERE l2.post_id=p.id
          AND l2.user_id=?
        )
        ELSE 0
      END liked,

      CASE
        WHEN ? IS NOT NULL
        THEN EXISTS(
          SELECT 1
          FROM saved_posts sp
          WHERE sp.post_id=CAST(p.id AS TEXT)
          AND sp.user_id=?
        )
        ELSE 0
      END saved

    FROM posts p
    JOIN users u ON u.id=p.user_id
    WHERE p.user_id=?
    ORDER BY p.id DESC
  `).bind(
    viewer?.id??null,
    viewer?.id??0,
    viewer?.id??null,
    viewer?.id??'',
    Number(u.id)
  ).all();

  return {
    user:{
      ...publicUser(u),
      followers_count:Number(followers?.c||0),
      following_count:Number(followingCount?.c||0),
      following
    },
    posts:posts.results||[]
  };
}

async function feed(env,user){
  const rows=await env.DB.prepare(`
    SELECT
      p.*,
      u.username,
      u.display_name,
      u.avatar_url,

      (SELECT COUNT(*)
       FROM likes l
       WHERE l.post_id=p.id) likes_count,

      (SELECT COUNT(*)
       FROM comments c
       WHERE c.post_id=p.id) comments_count,

      EXISTS(
        SELECT 1
        FROM likes l2
        WHERE l2.post_id=p.id
        AND l2.user_id=?
      ) liked,

      EXISTS(
        SELECT 1
        FROM saved_posts sp
        WHERE sp.post_id=CAST(p.id AS TEXT)
        AND sp.user_id=?
      ) saved

    FROM posts p
    JOIN users u ON u.id=p.user_id

    WHERE
      p.user_id=?
      OR p.user_id IN (
        SELECT following_id
        FROM follows
        WHERE follower_id=?
      )

    ORDER BY p.id DESC
    LIMIT 100
  `).bind(
    Number(user.id),
    Number(user.id),
    Number(user.id),
    Number(user.id)
  ).all();

  const stories=await storyFeed(env,user);

  return {
    posts:rows.results||[],
    stories
  };
}

async function storyFeed(env,user){
  const r=await env.DB.prepare(`
    SELECT
      s.*,
      u.username,
      u.display_name,
      u.avatar_url
    FROM stories s
    JOIN users u ON u.id=s.user_id

    WHERE
      datetime(s.created_at)>datetime('now','-24 hours')
      AND (
        s.user_id=?
        OR s.user_id IN (
          SELECT following_id
          FROM follows
          WHERE follower_id=?
        )
      )

    ORDER BY s.id DESC
  `).bind(
    Number(user.id),
    Number(user.id)
  ).all();

  return r.results||[];
}

async function reels(env,user){
  const r=await env.DB.prepare(`
    SELECT
      r.*,
      u.username,
      u.display_name,
      u.avatar_url
    FROM reels r
    JOIN users u ON u.id=r.user_id
    ORDER BY r.id DESC
    LIMIT 100
  `).all();

  return r.results||[];
}


/* =========================================================
   SHARED CHAT THEMES
   ========================================================= */

const CHAT_THEMES={
  default:[
    '#111111',
    '#333333',
    '#666666'
  ],

  ocean:[
    '#0077FF',
    '#00B7FF',
    '#7C3AED'
  ],

  sunset:[
    '#FF512F',
    '#DD2476',
    '#FFB347'
  ],

  neon:[
    '#00F5A0',
    '#00D9F5',
    '#7C3AED'
  ],

  berry:[
    '#7F00FF',
    '#E100FF',
    '#FF4D8D'
  ],

  forest:[
    '#064E3B',
    '#10B981',
    '#A3E635'
  ],

  fire:[
    '#FF0844',
    '#FF4B2B',
    '#FFB000'
  ],

  sky:[
    '#2563EB',
    '#06B6D4',
    '#A5F3FC'
  ],

  candy:[
    '#EC4899',
    '#A855F7',
    '#60A5FA'
  ],

  royal:[
    '#312E81',
    '#7C3AED',
    '#C026D3'
  ]
};

async function ensureChatThemes(env){
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS chat_themes (
      chat_id INTEGER PRIMARY KEY,
      theme TEXT NOT NULL DEFAULT 'default',
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

async function getChatTheme(env,chatId){
  await ensureChatThemes(env);

  const row=await env.DB.prepare(`
    SELECT theme
    FROM chat_themes
    WHERE chat_id=?
  `).bind(Number(chatId)).first();

  const name=
    CHAT_THEMES[row?.theme]
      ? row.theme
      : 'default';

  return {
    name,
    colors:CHAT_THEMES[name]
  };
}

async function setChatTheme(env,user,chatId,theme){
  await ensureChatThemes(env);

  const member=await env.DB.prepare(`
    SELECT 1
    FROM chat_members
    WHERE chat_id=? AND user_id=?
  `).bind(
    Number(chatId),
    Number(user.id)
  ).first();

  if(!member)
    throw new HttpError(403,'Not a chat member');

  if(!CHAT_THEMES[theme])
    throw new HttpError(400,'Invalid chat theme');

  await env.DB.prepare(`
    INSERT INTO chat_themes
    (chat_id,theme,updated_at)
    VALUES (?,?,CURRENT_TIMESTAMP)

    ON CONFLICT(chat_id)
    DO UPDATE SET
      theme=excluded.theme,
      updated_at=CURRENT_TIMESTAMP
  `).bind(
    Number(chatId),
    theme
  ).run();

  return {
    name:theme,
    colors:CHAT_THEMES[theme]
  };
}


/* =========================================================
   CHAT
   ========================================================= */

async function chatSummary(env,user,chatId){
  const c=await env.DB.prepare(
    'SELECT * FROM chats WHERE id=?'
  ).bind(Number(chatId)).first();

  if(!c)
    throw new HttpError(404,'Chat not found');

  const member=await env.DB.prepare(`
    SELECT 1
    FROM chat_members
    WHERE chat_id=? AND user_id=?
  `).bind(
    Number(chatId),
    Number(user.id)
  ).first();

  if(!member)
    throw new HttpError(403,'Not a chat member');

  if(c.is_group){
    return {
      id:Number(c.id),
      name:c.name||'Group',
      avatar_url:'',
      is_group:true,
      type:'group'
    };
  }

  const other=await env.DB.prepare(`
    SELECT u.*
    FROM chat_members cm
    JOIN users u ON u.id=cm.user_id
    WHERE cm.chat_id=?
      AND cm.user_id<>?
    LIMIT 1
  `).bind(
    Number(chatId),
    Number(user.id)
  ).first();

  return {
    id:Number(c.id),
    name:other?.display_name||other?.username||'Chat',
    username:other?.username||'',
    avatar_url:other?.avatar_url||'',
    user:publicUser(other),
    is_group:false,
    type:'direct'
  };
}

async function chatList(env,user){
  const r=await env.DB.prepare(`
    SELECT
      c.id,
      c.name,
      c.is_group,

      (
        SELECT content
        FROM messages m
        WHERE m.chat_id=c.id
        ORDER BY m.id DESC
        LIMIT 1
      ) last_message,

      (
        SELECT created_at
        FROM messages m2
        WHERE m2.chat_id=c.id
        ORDER BY m2.id DESC
        LIMIT 1
      ) last_message_at

    FROM chats c
    JOIN chat_members me
      ON me.chat_id=c.id
      AND me.user_id=?

    ORDER BY
      COALESCE(last_message_at,c.created_at) DESC
  `).bind(Number(user.id)).all();

  const out=[];

  for(const c of (r.results||[])){
    const s=await chatSummary(env,user,c.id);

    out.push({
      ...s,
      last_message:c.last_message||''
    });
  }

  return out;
}

async function createDirectChat(env,user,targetId){
  targetId=Number(targetId);

  if(!targetId || targetId===Number(user.id))
    throw new HttpError(400,'Invalid user');

  const target=await env.DB.prepare(`
    SELECT id,username,display_name,avatar_url
    FROM users
    WHERE id=?
  `).bind(targetId).first();

  if(!target)
    throw new HttpError(404,'User not found');

  const set=await getSettings(env,targetId);

  if(set.message_privacy==='nobody')
    throw new HttpError(403,'This user does not accept messages');

  if(set.message_privacy==='followers'){
    const f=await env.DB.prepare(`
      SELECT 1
      FROM follows
      WHERE follower_id=? AND following_id=?
    `).bind(
      Number(user.id),
      targetId
    ).first();

    if(!f)
      throw new HttpError(
        403,
        'Follow this user before messaging them'
      );
  }

  const existing=await env.DB.prepare(`
    SELECT c.id
    FROM chats c

    JOIN chat_members a
      ON a.chat_id=c.id
      AND a.user_id=?

    JOIN chat_members b
      ON b.chat_id=c.id
      AND b.user_id=?

    WHERE c.is_group=0
    LIMIT 1
  `).bind(
    Number(user.id),
    targetId
  ).first();

  if(existing)
    return await chatSummary(
      env,
      user,
      existing.id
    );

  const cr=await env.DB.prepare(`
    INSERT INTO chats
    (name,is_group)
    VALUES (?,0)
  `).bind('').run();

  const id=Number(cr.meta.last_row_id);

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO chat_members
      (chat_id,user_id)
      VALUES (?,?)
    `).bind(
      id,
      Number(user.id)
    ),

    env.DB.prepare(`
      INSERT INTO chat_members
      (chat_id,user_id)
      VALUES (?,?)
    `).bind(
      id,
      targetId
    )
  ]);

  return await chatSummary(
    env,
    user,
    id
  );
}

async function createGroup(env,user,body){
  const name=clean(
    body.name,
    60
  )||'New group';

  let ids=
    Array.isArray(body.user_ids)
      ? body.user_ids.map(Number).filter(Boolean)
      : [];

  ids=[
    ...new Set(ids)
  ].filter(
    x=>x!==Number(user.id)
  );

  if(ids.length>49)
    throw new HttpError(
      400,
      'A group can have at most 50 members'
    );

  if(ids.length){
    const qs=ids.map(
      ()=>'?'
    ).join(',');

    const rows=await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE id IN (${qs})
    `).bind(...ids).all();

    if(
      (rows.results||[]).length!==ids.length
    ){
      throw new HttpError(
        400,
        'One or more users were not found'
      );
    }
  }

  const cr=await env.DB.prepare(`
    INSERT INTO chats
    (name,is_group)
    VALUES (?,1)
  `).bind(name).run();

  const id=Number(
    cr.meta.last_row_id
  );

  const stmts=[
    env.DB.prepare(`
      INSERT INTO chat_members
      (chat_id,user_id)
      VALUES (?,?)
    `).bind(
      id,
      Number(user.id)
    ),

    ...ids.map(
      x=>env.DB.prepare(`
        INSERT INTO chat_members
        (chat_id,user_id)
        VALUES (?,?)
      `).bind(id,x)
    )
  ];

  await env.DB.batch(stmts);

  return await chatSummary(
    env,
    user,
    id
  );
}

async function sendMessage(
  env,
  user,
  chatId,
  content
){
  const member=await env.DB.prepare(`
    SELECT 1
    FROM chat_members
    WHERE chat_id=? AND user_id=?
  `).bind(
    Number(chatId),
    Number(user.id)
  ).first();

  if(!member)
    throw new HttpError(
      403,
      'Not a chat member'
    );

  const text=clean(
    content,
    5000
  );

  if(!text)
    throw new HttpError(
      400,
      'Message is empty'
    );

  const r=await env.DB.prepare(`
    INSERT INTO messages
    (chat_id,user_id,content,media_url)
    VALUES (?,?,?,?)
  `).bind(
    Number(chatId),
    Number(user.id),
    text,
    ''
  ).run();

  const msg=await env.DB.prepare(`
    SELECT
      m.*,
      u.username,
      u.display_name,
      u.avatar_url

    FROM messages m
    JOIN users u ON u.id=m.user_id

    WHERE m.id=?
  `).bind(
    Number(r.meta.last_row_id)
  ).first();

  const members=await env.DB.prepare(`
    SELECT user_id
    FROM chat_members
    WHERE chat_id=?
      AND user_id<>?
  `).bind(
    Number(chatId),
    Number(user.id)
  ).all();

  for(
    const m of (members.results||[])
  ){
    await notify(
      env,
      {
        userId:m.user_id,
        actorId:user.id,
        type:'message'
      }
    );
  }

  return msg;
}


/* =========================================================
   PASSWORD RESET
   ========================================================= */

async function sendResetEmail(
  env,
  email,
  code
){
  if(
    !env.RESEND_API_KEY ||
    !env.RESET_FROM_EMAIL
  ){
    throw new HttpError(
      503,
      'Password recovery email is not configured yet'
    );
  }

  const response=await fetch(
    'https://api.resend.com/emails',
    {
      method:'POST',

      headers:{
        Authorization:
          `Bearer ${env.RESEND_API_KEY}`,

        'Content-Type':
          'application/json'
      },

      body:JSON.stringify({
        from:env.RESET_FROM_EMAIL,

        to:[email],

        subject:
          'Your ZILNET password reset code',

        html:`
          <div style="font-family:Arial,sans-serif;line-height:1.5">
            <h2>ZILNET password reset</h2>
            <p>Your verification code is:</p>

            <div style="
              font-size:32px;
              font-weight:800;
              letter-spacing:8px
            ">
              ${code}
            </div>

            <p>
              This code expires in
              ${RESET_MINUTES} minutes.
            </p>

            <p>
              If you did not request this,
              you can ignore this email.
            </p>
          </div>
        `
      })
    }
  );

  if(!response.ok)
    throw new HttpError(
      502,
      'Could not send recovery email'
    );
}


/* =========================================================
   ROUTES
   ========================================================= */

async function route(req,env){
  const url=new URL(req.url);

  const path=
    url.pathname.replace(/\/$/,'')||'/';

  const method=
    req.method.toUpperCase();


  /* SIGNUP */

  if(
    path==='/api/signup' &&
    method==='POST'
  ){
    const b=await readJSON(req);

    const username=
      clean(b.username,30);

    const email=
      clean(b.email,200)
      .toLowerCase();

    const password=
      String(b.password||'');

    if(!usernameValid(username))
      throw new HttpError(
        400,
        'Username must be 3-30 characters and use letters, numbers, dot, dash or underscore'
      );

    if(!emailValid(email))
      throw new HttpError(
        400,
        'A valid email is required'
      );

    if(password.length<8)
      throw new HttpError(
        400,
        'Password must be at least 8 characters'
      );

    if(
      await env.DB.prepare(`
        SELECT id
        FROM users
        WHERE lower(username)=lower(?)
      `).bind(username).first()
    ){
      throw new HttpError(
        409,
        'Username already exists'
      );
    }

    if(
      await env.DB.prepare(`
        SELECT id
        FROM users
        WHERE lower(email)=lower(?)
      `).bind(email).first()
    ){
      throw new HttpError(
        409,
        'Email already exists'
      );
    }

    const ph=
      await hashPassword(password);

    const r=await env.DB.prepare(`
      INSERT INTO users
      (username,email,password_hash)
      VALUES (?,?,?)
    `).bind(
      username,
      email,
      ph
    ).run();

    const id=
      Number(r.meta.last_row_id);

    await env.DB.prepare(`
      INSERT OR IGNORE INTO user_settings
      (user_id)
      VALUES (?)
    `).bind(String(id)).run();

    const token=
      randomToken(32);

    await env.DB.prepare(`
      INSERT INTO sessions
      (user_id,token,expires_at)
      VALUES (?,?,?)
    `).bind(
      id,
      token,
      Date.now()+
      SESSION_DAYS*86400000
    ).run();

    return json(
      {
        user:ownUser(
          await env.DB.prepare(
            'SELECT * FROM users WHERE id=?'
          ).bind(id).first()
        )
      },
      200,
      {
        'Set-Cookie':
          cookie(token)
      }
    );
  }


  /* LOGIN */

  if(
    path==='/api/login' &&
    method==='POST'
  ){
    const b=await readJSON(req);

    const identity=
      clean(
        b.username||b.email,
        200
      ).toLowerCase();

    const password=
      String(b.password||'');

    const u=await env.DB.prepare(`
      SELECT *
      FROM users
      WHERE lower(username)=?
         OR lower(email)=?
      LIMIT 1
    `).bind(
      identity,
      identity
    ).first();

    if(
      !u ||
      !(await verifyPassword(
        password,
        u.password_hash
      ))
    ){
      throw new HttpError(
        401,
        'Invalid username/email or password'
      );
    }

    const token=
      randomToken(32);

    await env.DB.prepare(`
      INSERT INTO sessions
      (user_id,token,expires_at)
      VALUES (?,?,?)
    `).bind(
      Number(u.id),
      token,
      Date.now()+
      SESSION_DAYS*86400000
    ).run();

    return json(
      {
        user:ownUser(u)
      },
      200,
      {
        'Set-Cookie':
          cookie(token)
      }
    );
  }


  /* LOGOUT */

  if(
    path==='/api/logout' &&
    method==='POST'
  ){
    const t=
      getCookie(
        req,
        'zilnet_session'
      );

    if(t){
      await env.DB.prepare(
        'DELETE FROM sessions WHERE token=?'
      ).bind(t).run();
    }

    return json(
      {ok:true},
      200,
      {
        'Set-Cookie':
          clearCookie()
      }
    );
  }


  /* CURRENT USER */

  if(
    path==='/api/me' &&
    method==='GET'
  ){
    const u=
      await requireUser(
        req,
        env
      );

    return ok({
      user:ownUser(u)
    });
  }


  /* FORGOT PASSWORD */

  if(
    path==='/api/forgot-password' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    const email=
      clean(
        b.email,
        200
      ).toLowerCase();

    if(!emailValid(email))
      throw new HttpError(
        400,
        'Enter a valid email address'
      );

    const u=
      await env.DB.prepare(`
        SELECT id,email
        FROM users
        WHERE lower(email)=?
      `).bind(email).first();

    const id=
      crypto.randomUUID();

    if(u){
      const code=
        String(
          Math.floor(
            100000+
            Math.random()*900000
          )
        );

      const hash=
        await sha256(code);

      await env.DB.prepare(`
        DELETE FROM password_resets
        WHERE user_id=?
      `).bind(
        String(u.id)
      ).run();

      await env.DB.prepare(`
        INSERT INTO password_resets
        (id,user_id,token_hash,expires_at,created_at)
        VALUES (?,?,?,?,?)
      `).bind(
        id,
        String(u.id),
        hash,
        Date.now()+
        RESET_MINUTES*60000,
        new Date().toISOString()
      ).run();

      await sendResetEmail(
        env,
        email,
        code
      );
    }

    return ok({
      message:
        'If an account matches that email, a verification code has been sent.',
      reset_id:id
    });
  }


  /* RESET PASSWORD */

  if(
    path==='/api/reset-password' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    const resetId=
      clean(
        b.reset_id,
        100
      );

    const code=
      clean(
        b.code,
        20
      );

    const newPassword=
      String(
        b.new_password||
        b.password||
        ''
      );

    if(
      !resetId ||
      !/^\d{6}$/.test(code) ||
      newPassword.length<8
    ){
      throw new HttpError(
        400,
        'Invalid reset details'
      );
    }

    const hash=
      await sha256(code);

    const r=
      await env.DB.prepare(`
        SELECT *
        FROM password_resets
        WHERE id=?
          AND token_hash=?
          AND expires_at>?
      `).bind(
        resetId,
        hash,
        Date.now()
      ).first();

    if(!r)
      throw new HttpError(
        400,
        'Invalid or expired verification code'
      );

    const ph=
      await hashPassword(
        newPassword
      );

    await env.DB.prepare(`
      UPDATE users
      SET password_hash=?,
          password_salt=?
      WHERE id=?
    `).bind(
      ph,
      '',
      Number(r.user_id)
    ).run();

    await env.DB.prepare(`
      DELETE FROM password_resets
      WHERE id=?
    `).bind(resetId).run();

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id=?
    `).bind(
      Number(r.user_id)
    ).run();

    const token=
      randomToken(32);

    await env.DB.prepare(`
      INSERT INTO sessions
      (user_id,token,expires_at)
      VALUES (?,?,?)
    `).bind(
      Number(r.user_id),
      token,
      Date.now()+
      SESSION_DAYS*86400000
    ).run();

    return json(
      {
        ok:true,

        user:ownUser(
          await env.DB.prepare(
            'SELECT * FROM users WHERE id=?'
          ).bind(
            Number(r.user_id)
          ).first()
        )
      },
      200,
      {
        'Set-Cookie':
          cookie(token)
      }
    );
  }


  /* MEDIA */

  if(
    path.startsWith('/media/') &&
    method==='GET'
  ){
    if(!env.MEDIA)
      throw new HttpError(
        503,
        'Media storage is not configured'
      );

    const key=
      decodeURIComponent(
        path.slice('/media/'.length)
      );

    const obj=
      await env.MEDIA.get(key);

    if(!obj)
      return new Response(
        'Not found',
        {status:404}
      );

    const h=
      new Headers();

    obj.writeHttpMetadata(h);

    h.set(
      'etag',
      obj.httpEtag
    );

    h.set(
      'cache-control',
      'public, max-age=31536000'
    );

    return new Response(
      obj.body,
      {headers:h}
    );
  }


  const user=
    await requireUser(
      req,
      env
    );


  /* PROFILE */

  if(
    path==='/api/profile' &&
    method==='GET'
  ){
    return ok(
      await getPublicProfile(
        env,
        user,
        user.username
      )
    );
  }

  if(
    path==='/api/profile/update' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    const display=
      clean(
        b.display_name,
        80
      );

    const bio=
      clean(
        b.bio,
        500
      );

    const skills=
      clean(
        b.skills,
        500
      );

    const avatar=
      clean(
        b.avatar_url,
        1000
      );

    await env.DB.prepare(`
      UPDATE users
      SET display_name=?,
          bio=?,
          skills=?,
          avatar_url=?
      WHERE id=?
    `).bind(
      display,
      bio,
      skills,
      avatar,
      Number(user.id)
    ).run();

    return ok({
      user:ownUser(
        await env.DB.prepare(
          'SELECT * FROM users WHERE id=?'
        ).bind(
          Number(user.id)
        ).first()
      )
    });
  }


  /* PASSWORD CHANGE */

  if(
    path==='/api/profile/password' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    if(
      !(await verifyPassword(
        String(
          b.current_password||''
        ),
        user.password_hash
      ))
    ){
      throw new HttpError(
        401,
        'Current password is incorrect'
      );
    }

    if(
      String(
        b.new_password||''
      ).length<8
    ){
      throw new HttpError(
        400,
        'New password must be at least 8 characters'
      );
    }

    const ph=
      await hashPassword(
        String(
          b.new_password
        )
      );

    await env.DB.prepare(`
      UPDATE users
      SET password_hash=?
      WHERE id=?
    `).bind(
      ph,
      Number(user.id)
    ).run();

    return ok({
      ok:true
    });
  }


  /* PUBLIC USER PROFILE */

  const pm=
    path.match(
      /^\/api\/(?:profile|users)\/([^/]+)$/
    );

  if(
    pm &&
    method==='GET'
  ){
    return ok(
      await getPublicProfile(
        env,
        user,
        decodeURIComponent(
          pm[1]
        )
      )
    );
  }


  /* SEARCH */

  if(
    path==='/api/search' &&
    method==='GET'
  ){
    const q=
      clean(
        url.searchParams.get('q'),
        100
      );

    let users;

    if(q){
      users=
        await env.DB.prepare(`
          SELECT
            u.id,
            u.username,
            u.display_name,
            u.bio,
            u.avatar_url,
            u.skills,

            EXISTS(
              SELECT 1
              FROM follows f
              WHERE f.follower_id=?
                AND f.following_id=u.id
            ) following

          FROM users u

          WHERE
            lower(u.username) LIKE lower(?)
            OR lower(u.display_name) LIKE lower(?)
            OR lower(u.skills) LIKE lower(?)

          ORDER BY u.username
          LIMIT 50
        `).bind(
          Number(user.id),
          `%${q}%`,
          `%${q}%`,
          `%${q}%`
        ).all();

    }else{

      users=
        await env.DB.prepare(`
          SELECT
            u.id,
            u.username,
            u.display_name,
            u.bio,
            u.avatar_url,
            u.skills,

            EXISTS(
              SELECT 1
              FROM follows f
              WHERE f.follower_id=?
                AND f.following_id=u.id
            ) following

          FROM users u

          WHERE u.id<>?

          ORDER BY u.id DESC
          LIMIT 50
        `).bind(
          Number(user.id),
          Number(user.id)
        ).all();
    }

    return ok({
      users:users.results||[]
    });
  }


  /* FOLLOW */

  const fm=
    path.match(
      /^\/api\/users\/(\d+)\/follow$/
    );

  if(
    fm &&
    method==='POST'
  ){
    const target=
      Number(fm[1]);

    if(
      target===Number(user.id)
    ){
      throw new HttpError(
        400,
        'You cannot follow yourself'
      );
    }

    if(
      !(await env.DB.prepare(
        'SELECT id FROM users WHERE id=?'
      ).bind(target).first())
    ){
      throw new HttpError(
        404,
        'User not found'
      );
    }

    const ex=
      await env.DB.prepare(`
        SELECT id
        FROM follows
        WHERE follower_id=?
          AND following_id=?
      `).bind(
        Number(user.id),
        target
      ).first();

    if(ex){
      await env.DB.prepare(
        'DELETE FROM follows WHERE id=?'
      ).bind(ex.id).run();

      return ok({
        following:false
      });
    }

    await env.DB.prepare(`
      INSERT INTO follows
      (follower_id,following_id)
      VALUES (?,?)
    `).bind(
      Number(user.id),
      target
    ).run();

    await notify(
      env,
      {
        userId:target,
        actorId:user.id,
        type:'follow'
      }
    );

    return ok({
      following:true
    });
  }


  /* FEED */

  if(
    path==='/api/feed' &&
    method==='GET'
  ){
    return ok(
      await feed(
        env,
        user
      )
    );
  }


  /* CREATE POST */

  if(
    path==='/api/posts' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    const content=
      clean(
        b.content,
        10000
      );

    const media=
      clean(
        b.media_url,
        2000
      );

    const type=
      clean(
        b.media_type,
        100
      );

    if(!content&&!media)
      throw new HttpError(
        400,
        'Post needs text or media'
      );

    const r=
      await env.DB.prepare(`
        INSERT INTO posts
        (user_id,content,media_url,media_type)
        VALUES (?,?,?,?)
      `).bind(
        Number(user.id),
        content,
        media,
        type
      ).run();

    const p=
      await env.DB.prepare(`
        SELECT
          p.*,
          u.username,
          u.display_name,
          u.avatar_url,
          0 likes_count,
          0 comments_count,
          0 liked,
          0 saved

        FROM posts p
        JOIN users u ON u.id=p.user_id

        WHERE p.id=?
      `).bind(
        Number(r.meta.last_row_id)
      ).first();

    return ok({
      post:p
    });
  }


  /* POST */

  const postId=
    path.match(
      /^\/api\/posts\/(\d+)$/
    );

  if(
    postId &&
    method==='GET'
  ){
    const id=
      Number(postId[1]);

    const p=
      await env.DB.prepare(`
        SELECT
          p.*,
          u.username,
          u.display_name,
          u.avatar_url,

          (
            SELECT COUNT(*)
            FROM likes
            WHERE post_id=p.id
          ) likes_count,

          (
            SELECT COUNT(*)
            FROM comments
            WHERE post_id=p.id
          ) comments_count,

          EXISTS(
            SELECT 1
            FROM likes
            WHERE post_id=p.id
              AND user_id=?
          ) liked,

          EXISTS(
            SELECT 1
            FROM saved_posts
            WHERE post_id=CAST(p.id AS TEXT)
              AND user_id=?
          ) saved

        FROM posts p
        JOIN users u ON u.id=p.user_id

        WHERE p.id=?
      `).bind(
        Number(user.id),
        String(user.id),
        id
      ).first();

    if(!p)
      throw new HttpError(
        404,
        'Post not found'
      );

    return ok({
      post:p
    });
  }


  /* DELETE POST */

  if(
    postId &&
    method==='DELETE'
  ){
    const id=
      Number(postId[1]);

    const p=
      await env.DB.prepare(
        'SELECT user_id FROM posts WHERE id=?'
      ).bind(id).first();

    if(!p)
      throw new HttpError(
        404,
        'Post not found'
      );

    if(
      Number(p.user_id)!==
      Number(user.id)
    ){
      throw new HttpError(
        403,
        'You can only delete your own posts'
      );
    }

    await env.DB.batch([
      env.DB.prepare(
        'DELETE FROM comments WHERE post_id=?'
      ).bind(id),

      env.DB.prepare(
        'DELETE FROM likes WHERE post_id=?'
      ).bind(id),

      env.DB.prepare(
        'DELETE FROM saved_posts WHERE post_id=?'
      ).bind(String(id)),

      env.DB.prepare(
        'DELETE FROM notifications WHERE post_id=?'
      ).bind(id),

      env.DB.prepare(
        'DELETE FROM posts WHERE id=?'
      ).bind(id)
    ]);

    return ok({
      ok:true
    });
  }


  /* LIKE */

  const likeM=
    path.match(
      /^\/api\/posts\/(\d+)\/like$/
    );

  if(
    likeM &&
    method==='POST'
  ){
    const id=
      Number(likeM[1]);

    if(
      !(await env.DB.prepare(
        'SELECT id FROM posts WHERE id=?'
      ).bind(id).first())
    ){
      throw new HttpError(
        404,
        'Post not found'
      );
    }

    const ex=
      await env.DB.prepare(`
        SELECT id
        FROM likes
        WHERE post_id=?
          AND user_id=?
      `).bind(
        id,
        Number(user.id)
      ).first();

    if(ex){

      await env.DB.prepare(
        'DELETE FROM likes WHERE id=?'
      ).bind(ex.id).run();

    }else{

      await env.DB.prepare(`
        INSERT INTO likes
        (post_id,user_id)
        VALUES (?,?)
      `).bind(
        id,
        Number(user.id)
      ).run();

      const p=
        await env.DB.prepare(
          'SELECT user_id FROM posts WHERE id=?'
        ).bind(id).first();

      await notify(
        env,
        {
          userId:p.user_id,
          actorId:user.id,
          type:'like',
          postId:id
        }
      );
    }

    const c=
      await env.DB.prepare(`
        SELECT COUNT(*) c
        FROM likes
        WHERE post_id=?
      `).bind(id).first();

    return ok({
      liked:!ex,
      likes_count:
        Number(c?.c||0)
    });
  }


  /* SAVE */

  const saveM=
    path.match(
      /^\/api\/posts\/(\d+)\/save$/
    );

  if(
    saveM &&
    method==='POST'
  ){
    const id=
      Number(saveM[1]);

    if(
      !(await env.DB.prepare(
        'SELECT id FROM posts WHERE id=?'
      ).bind(id).first())
    ){
      throw new HttpError(
        404,
        'Post not found'
      );
    }

    const ex=
      await env.DB.prepare(`
        SELECT post_id
        FROM saved_posts
        WHERE post_id=?
          AND user_id=?
      `).bind(
        String(id),
        String(user.id)
      ).first();

    if(ex){

      await env.DB.prepare(`
        DELETE FROM saved_posts
        WHERE post_id=?
          AND user_id=?
      `).bind(
        String(id),
        String(user.id)
      ).run();

    }else{

      await env.DB.prepare(`
        INSERT INTO saved_posts
        (post_id,user_id,created_at)
        VALUES (?,?,?)
      `).bind(
        String(id),
        String(user.id),
        new Date().toISOString()
      ).run();
    }

    return ok({
      saved:!ex
    });
  }


  /* COMMENTS */

  const cm=
    path.match(
      /^\/api\/posts\/(\d+)\/comments$/
    );

  if(
    cm &&
    method==='GET'
  ){
    const id=
      Number(cm[1]);

    const r=
      await env.DB.prepare(`
        SELECT
          c.*,
          u.username,
          u.display_name,
          u.avatar_url

        FROM comments c
        JOIN users u ON u.id=c.user_id

        WHERE c.post_id=?

        ORDER BY c.id ASC
      `).bind(id).all();

    return ok({
      comments:r.results||[]
    });
  }

  if(
    cm &&
    method==='POST'
  ){
    const id=
      Number(cm[1]);

    const b=
      await readJSON(req);

    const content=
      clean(
        b.content,
        3000
      );

    if(!content)
      throw new HttpError(
        400,
        'Comment is empty'
      );

    const p=
      await env.DB.prepare(
        'SELECT user_id FROM posts WHERE id=?'
      ).bind(id).first();

    if(!p)
      throw new HttpError(
        404,
        'Post not found'
      );

    const r=
      await env.DB.prepare(`
        INSERT INTO comments
        (post_id,user_id,content)
        VALUES (?,?,?)
      `).bind(
        id,
        Number(user.id),
        content
      ).run();

    const c=
      await env.DB.prepare(`
        SELECT
          c.*,
          u.username,
          u.display_name,
          u.avatar_url

        FROM comments c
        JOIN users u ON u.id=c.user_id

        WHERE c.id=?
      `).bind(
        Number(r.meta.last_row_id)
      ).first();

    await notify(
      env,
      {
        userId:p.user_id,
        actorId:user.id,
        type:'comment',
        postId:id
      }
    );

    return ok({
      comment:c
    });
  }


  /* STORIES */

  if(
    path==='/api/stories/feed' &&
    method==='GET'
  ){
    return ok({
      stories:
        await storyFeed(
          env,
          user
        )
    });
  }

  if(
    path==='/api/stories' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    const content=
      clean(
        b.content||b.text,
        5000
      );

    const media=
      clean(
        b.media_url,
        2000
      );

    const type=
      clean(
        b.media_type,
        100
      );

    if(!content&&!media)
      throw new HttpError(
        400,
        'Story needs text or media'
      );

    const r=
      await env.DB.prepare(`
        INSERT INTO stories
        (user_id,content,media_url,media_type)
        VALUES (?,?,?,?)
      `).bind(
        Number(user.id),
        content,
        media,
        type
      ).run();

    return ok({
      story:
        await env.DB.prepare(`
          SELECT
            s.*,
            u.username,
            u.display_name,
            u.avatar_url

          FROM stories s
          JOIN users u ON u.id=s.user_id

          WHERE s.id=?
        `).bind(
          Number(r.meta.last_row_id)
        ).first()
    });
  }


  /* REELS */

  if(
    path==='/api/reels/feed' &&
    method==='GET'
  ){
    return ok({
      reels:
        await reels(
          env,
          user
        )
    });
  }

  if(
    path==='/api/reels' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    const caption=
      clean(
        b.caption,
        5000
      );

    const media=
      clean(
        b.media_url||
        b.video_url,
        2000
      );

    if(!media)
      throw new HttpError(
        400,
        'Reel video is required'
      );

    const r=
      await env.DB.prepare(`
        INSERT INTO reels
        (user_id,caption,media_url)
        VALUES (?,?,?)
      `).bind(
        Number(user.id),
        caption,
        media
      ).run();

    return ok({
      reel:
        await env.DB.prepare(`
          SELECT
            r.*,
            u.username,
            u.display_name,
            u.avatar_url

          FROM reels r
          JOIN users u ON u.id=r.user_id

          WHERE r.id=?
        `).bind(
          Number(r.meta.last_row_id)
        ).first()
    });
  }


  /* CHATS */

  if(
    path==='/api/chats' &&
    method==='GET'
  ){
    return ok({
      chats:
        await chatList(
          env,
          user
        )
    });
  }

  if(
    path==='/api/chats' &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    return ok({
      chat:
        await createDirectChat(
          env,
          user,
          b.user_id||
          (b.user_ids||[])[0]
        )
    });
  }


  /* GROUPS */

  if(
    path==='/api/groups' &&
    method==='POST'
  ){
    return ok({
      chat:
        await createGroup(
          env,
          user,
          await readJSON(req)
        )
    });
  }


  /* =====================================================
     CHAT THEME GET
     Everyone in the chat can see the current theme.
     ===================================================== */

  const chatThemeM=
    path.match(
      /^\/api\/chats\/(\d+)\/theme$/
    );

  if(
    chatThemeM &&
    method==='GET'
  ){
    const chatId=
      Number(chatThemeM[1]);

    const member=
      await env.DB.prepare(`
        SELECT 1
        FROM chat_members
        WHERE chat_id=?
          AND user_id=?
      `).bind(
        chatId,
        Number(user.id)
      ).first();

    if(!member)
      throw new HttpError(
        403,
        'Not a chat member'
      );

    return ok({
      theme:
        await getChatTheme(
          env,
          chatId
        ),

      themes:
        Object.entries(
          CHAT_THEMES
        ).map(
          ([name,colors])=>({
            name,
            colors
          })
        )
    });
  }


  /* =====================================================
     CHAT THEME POST
     Changes the shared theme for the entire chat/group.
     ===================================================== */

  if(
    chatThemeM &&
    method==='POST'
  ){
    const chatId=
      Number(chatThemeM[1]);

    const b=
      await readJSON(req);

    return ok({
      theme:
        await setChatTheme(
          env,
          user,
          chatId,
          String(
            b.theme||
            'default'
          )
        )
    });
  }


  /* CHAT INFO */

  const chatM=
    path.match(
      /^\/api\/chats\/(\d+)$/
    );

  if(
    chatM &&
    method==='GET'
  ){
    return ok({
      chat:
        await chatSummary(
          env,
          user,
          Number(chatM[1])
        )
    });
  }


  /* MESSAGES */

  const msgM=
    path.match(
      /^\/api\/chats\/(\d+)\/messages$/
    );

  if(
    msgM &&
    method==='GET'
  ){
    const id=
      Number(msgM[1]);

    const member=
      await env.DB.prepare(`
        SELECT 1
        FROM chat_members
        WHERE chat_id=?
          AND user_id=?
      `).bind(
        id,
        Number(user.id)
      ).first();

    if(!member)
      throw new HttpError(
        403,
        'Not a chat member'
      );

    const r=
      await env.DB.prepare(`
        SELECT
          m.*,
          u.username,
          u.display_name,
          u.avatar_url

        FROM messages m
        JOIN users u ON u.id=m.user_id

        WHERE m.chat_id=?

        ORDER BY m.id ASC
        LIMIT 500
      `).bind(id).all();

    return ok({
      messages:r.results||[]
    });
  }

  if(
    msgM &&
    method==='POST'
  ){
    const b=
      await readJSON(req);

    return ok({
      message:
        await sendMessage(
          env,
          user,
          Number(msgM[1]),
          b.content
        )
    });
  }


  /* NOTIFICATIONS */

  if(
    path==='/api/notifications' &&
    method==='GET'
  ){
    const r=
      await env.DB.prepare(`
        SELECT
          n.*,
          u.username actor_username,
          u.display_name actor_display_name,
          u.avatar_url actor_avatar_url,
          p.content post_content

        FROM notifications n

        LEFT JOIN users u
          ON u.id=n.actor_id

        LEFT JOIN posts p
          ON p.id=n.post_id

        WHERE n.user_id=?

        ORDER BY n.id DESC
        LIMIT 100
      `).bind(
        Number(user.id)
      ).all();

    return ok({
      notifications:
        (r.results||[]).map(
          n=>({
            ...n,

            read:Boolean(
              n.is_read
            ),

            actor:{
              id:n.actor_id,
              username:n.actor_username,
              display_name:
                n.actor_display_name,
              avatar_url:
                n.actor_avatar_url
            }
          })
        )
    });
  }


  if(
    path==='/api/notifications/read' &&
    method==='POST'
  ){
    await env.DB.prepare(`
      UPDATE notifications
      SET is_read=1
      WHERE user_id=?
    `).bind(
      Number(user.id)
    ).run();

    return ok({
      ok:true
    });
  }


  /* SETTINGS */

  if(
    path==='/api/settings' &&
    (
      method==='GET'||
      method==='POST'||
      method==='PATCH'
    )
  ){
    const s=
      await getSettings(
        env,
        user.id
      );

    if(method==='GET')
      return ok({
        settings:s
      });

    const b=
      await readJSON(req);

    const theme=
      [
        'system',
        'dark',
        'light'
      ].includes(b.theme)
        ? b.theme
        : s.theme;

    const pv=
      [
        'public',
        'private'
      ].includes(
        b.profile_visibility
      )
        ? b.profile_visibility
        : s.profile_visibility;

    const mp=
      [
        'everyone',
        'followers',
        'nobody'
      ].includes(
        b.message_privacy
      )
        ? b.message_privacy
        : s.message_privacy;

    const ns=
      typeof b.notification_settings==='object' &&
      b.notification_settings
        ? {
            ...s.notification_settings,
            ...b.notification_settings
          }
        : s.notification_settings;

    await env.DB.prepare(`
      INSERT INTO user_settings
      (
        user_id,
        theme,
        profile_visibility,
        message_privacy,
        notification_settings
      )
      VALUES (?,?,?,?,?)

      ON CONFLICT(user_id)
      DO UPDATE SET
        theme=excluded.theme,
        profile_visibility=excluded.profile_visibility,
        message_privacy=excluded.message_privacy,
        notification_settings=excluded.notification_settings
    `).bind(
      String(user.id),
      theme,
      pv,
      mp,
      JSON.stringify(ns)
    ).run();

    return ok({
      settings:
        await getSettings(
          env,
          user.id
        )
    });
  }


  /* UPLOAD */

  if(
    path==='/api/upload' &&
    method==='POST'
  ){
    if(!env.MEDIA)
      throw new HttpError(
        503,
        'Media storage is not configured'
      );

    const form=
      await req.formData();

    const file=
      form.get('file');

    if(!(file instanceof File))
      throw new HttpError(
        400,
        'Choose a file'
      );

    if(
      file.size>
      50*1024*1024
    ){
      throw new HttpError(
        413,
        'File is too large (50 MB maximum)'
      );
    }

    const ext=
      (
        file.name.match(
          /\.[a-zA-Z0-9]{1,10}$/
        )||['']
      )[0].toLowerCase();

    const key=
      `media/${user.id}/${
        Date.now()
      }-${
        randomToken(8)
      }${ext}`;

    await env.MEDIA.put(
      key,
      file.stream(),
      {
        httpMetadata:{
          contentType:
            file.type||
            'application/octet-stream',

          cacheControl:
            'public, max-age=31536000'
        }
      }
    );

    return ok({
      url:
        `/media/${
          encodeURIComponent(key)
        }`,

      key
    });
  }


  return new HttpError(
    404,
    'Route not found'
  );
}


export default {
  async fetch(
    req,
    env
  ){
    try{
      const r=
        await route(
          req,
          env
        );

      return r instanceof HttpError
        ? fail(
            r.status,
            r.message
          )
        : r;

    }catch(e){

      if(
        e instanceof HttpError
      ){
        return fail(
          e.status,
          e.message
        );
      }

      console.error(e);

      return fail(
        500,
        'Internal server error'
      );
    }
  }
};
