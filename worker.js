const SESSION_DAYS = 30;
const RESET_MINUTES = 15;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extra
    }
  });
}

function error(status, message) {
  return json({ error: message }, status);
}

async function readJSON(req) {
  try {
    return await req.json();
  } catch {
    throw new HttpError(400, "Invalid JSON");
  }
}

function clean(v, max = 10000) {
  return String(v ?? "").trim().slice(0, max);
}

function usernameOK(v) {
  return /^[A-Za-z0-9_.-]{3,30}$/.test(v);
}

function emailOK(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function now() {
  return new Date().toISOString();
}

function token(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);

  return btoa(String.fromCharCode(...a))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

const id = token;

function getCookie(req, name) {
  const raw = req.headers.get("Cookie") || "";

  for (const part of raw.split(";")) {
    const pieces = part.trim().split("=");

    if (pieces[0] === name) {
      return pieces.slice(1).join("=");
    }
  }

  return "";
}

function setSession(value) {
  return [
    `zilnet_session=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function clearSession() {
  return [
    "zilnet_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

async function sha256(text) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );

  return [...new Uint8Array(buf)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function hashPassword(
  password,
  salt = token(16),
  iterations = 120000
) {
  const normalized = salt
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(salt.length / 4) * 4, "=");

  const saltBytes = Uint8Array.from(
    atob(normalized),
    c => c.charCodeAt(0)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$sha256$${iterations}$${salt}$${b64(bits)}`;
}

async function verifyPassword(password, stored) {
  const value = String(stored || "");

  const parts = value.split("$");

  if (
    parts.length === 5 &&
    parts[0] === "pbkdf2" &&
    parts[1] === "sha256"
  ) {
    const iterations = Number(parts[2]);

    if (
      Number.isInteger(iterations) &&
      iterations >= 10000 &&
      iterations <= 1000000
    ) {
      const check = await hashPassword(
        password,
        parts[3],
        iterations
      );

      return check === value;
    }
  }

  return false;
}

/*
  The live database currently uses INTEGER ids for users/sessions.
  These helpers deliberately work with that schema.
*/

async function tableColumns(env, table) {
  const result = await env.DB
    .prepare(`PRAGMA table_info(${table})`)
    .all();

  return (result.results || []).map(x => x.name);
}

async function hasColumn(env, table, column) {
  const cols = await tableColumns(env, table);
  return cols.includes(column);
}

async function insertUser(
  env,
  username,
  email,
  displayName,
  passwordHash
) {
  const columns = await tableColumns(env, "users");

  const values = [];
  const names = [];

  function add(name, value) {
    if (columns.includes(name)) {
      names.push(name);
      values.push(value);
    }
  }

  add("username", username);
  add("email", email);
  add("display_name", displayName);
  add("bio", "");
  add("avatar_url", "");
  add("skills", "");
  add("password_hash", passwordHash);
  add("password_salt", "");
  add("created_at", now());
  add("is_private", 0);

  const marks = names.map(() => "?").join(",");

  const result = await env.DB
    .prepare(`
      INSERT INTO users
      (${names.join(",")})
      VALUES (${marks})
    `)
    .bind(...values)
    .run();

  return Number(result.meta.last_row_id);
}

async function findUser(env, identifier) {
  return env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE lower(username)=lower(?)
         OR lower(email)=lower(?)
      LIMIT 1
    `)
    .bind(identifier, identifier)
    .first();
}

async function getUserById(env, userId) {
  return env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE id=?
      LIMIT 1
    `)
    .bind(Number(userId))
    .first();
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: Number(user.id),
    username: user.username || "",
    display_name: user.display_name || "",
    bio: user.bio || "",
    avatar_url: user.avatar_url || "",
    skills: user.skills || "",
    created_at: user.created_at || ""
  };
}

function ownUser(user) {
  if (!user) return null;

  return {
    ...publicUser(user),
    email: user.email || ""
  };
}

async function ensureSettings(env, userId) {
  let row = await env.DB
    .prepare(`
      SELECT *
      FROM user_settings
      WHERE user_id=?
      LIMIT 1
    `)
    .bind(String(userId))
    .first();

  if (!row) {
    await env.DB
      .prepare(`
        INSERT OR IGNORE INTO user_settings
        (
          user_id,
          theme,
          profile_visibility,
          message_privacy,
          notification_settings
        )
        VALUES (?,?,?,?,?)
      `)
      .bind(
        String(userId),
        "system",
        "public",
        "everyone",
        "{}"
      )
      .run();

    row = await env.DB
      .prepare(`
        SELECT *
        FROM user_settings
        WHERE user_id=?
        LIMIT 1
      `)
      .bind(String(userId))
      .first();
  }

  let notifications = {};

  try {
    notifications = JSON.parse(
      row?.notification_settings || "{}"
    );
  } catch {}

  return {
    ...(row || {}),
    notification_settings: notifications
  };
}

async function requireUser(req, env) {
  const session = getCookie(
    req,
    "zilnet_session"
  );

  if (!session) {
    throw new HttpError(
      401,
      "Login required"
    );
  }

  /*
    Live D1 schema:
      sessions.id          INTEGER
      sessions.user_id     INTEGER
      sessions.token       TEXT
      sessions.expires_at  INTEGER
  */

  const user = await env.DB
    .prepare(`
      SELECT u.*
      FROM sessions s
      JOIN users u
        ON u.id=s.user_id
      WHERE s.token=?
        AND s.expires_at>?
      LIMIT 1
    `)
    .bind(
      session,
      Date.now()
    )
    .first();

  if (!user) {
    throw new HttpError(
      401,
      "Session expired"
    );
  }

  return user;
}

async function notify(
  env,
  userId,
  actorId,
  type,
  postId = null
) {
  if (
    Number(userId) ===
    Number(actorId)
  ) {
    return;
  }

  const exists = await env.DB
    .prepare(`
      SELECT name
      FROM sqlite_master
      WHERE type='table'
        AND name='notifications'
      LIMIT 1
    `)
    .first();

  if (!exists) return;

  await env.DB
    .prepare(`
      INSERT INTO notifications
      (
        user_id,
        actor_id,
        type,
        post_id,
        is_read,
        created_at
      )
      VALUES (?,?,?,?,0,?)
    `)
    .bind(
      Number(userId),
      Number(actorId),
      type,
      postId,
      now()
    )
    .run();
}

async function getProfile(
  env,
  viewer,
  username
) {
  const user =
    await env.DB
      .prepare(`
        SELECT *
        FROM users
        WHERE lower(username)=lower(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

  if (!user) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const settings =
    await ensureSettings(
      env,
      user.id
    );

  let followers = 0;
  let following = 0;
  let isFollowing = false;

  const followsExists =
    await env.DB
      .prepare(`
        SELECT name
        FROM sqlite_master
        WHERE type='table'
          AND name='follows'
        LIMIT 1
      `)
      .first();

  if (followsExists) {
    const a = await env.DB
      .prepare(`
        SELECT COUNT(*) c
        FROM follows
        WHERE following_id=?
      `)
      .bind(Number(user.id))
      .first();

    const b = await env.DB
      .prepare(`
        SELECT COUNT(*) c
        FROM follows
        WHERE follower_id=?
      `)
      .bind(Number(user.id))
      .first();

    followers = Number(a?.c || 0);
    following = Number(b?.c || 0);

    if (viewer) {
      isFollowing = !!(
        await env.DB
          .prepare(`
            SELECT 1
            FROM follows
            WHERE follower_id=?
              AND following_id=?
            LIMIT 1
          `)
          .bind(
            Number(viewer.id),
            Number(user.id)
          )
          .first()
      );
    }
  }

  const own =
    viewer &&
    Number(viewer.id) ===
      Number(user.id);

  if (
    settings.profile_visibility ===
      "private" &&
    !own &&
    !isFollowing
  ) {
    return {
      user: {
        ...publicUser(user),
        followers_count: followers,
        following_count: following,
        following: isFollowing
      },
      posts: [],
      private: true
    };
  }

  let posts = [];

  const postsExists =
    await env.DB
      .prepare(`
        SELECT name
        FROM sqlite_master
        WHERE type='table'
          AND name='posts'
        LIMIT 1
      `)
      .first();

  if (postsExists) {
    const r = await env.DB
      .prepare(`
        SELECT
          p.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM posts p
        JOIN users u
          ON u.id=p.user_id
        WHERE p.user_id=?
        ORDER BY p.id DESC
        LIMIT 100
      `)
      .bind(Number(user.id))
      .all();

    posts = r.results || [];
  }

  return {
    user: {
      ...publicUser(user),
      followers_count: followers,
      following_count: following,
      following: isFollowing
    },
    posts
  };
}
async function createSession(env, userId) {
  const rawToken = token(48);
  const expiresAt =
    Date.now() +
    SESSION_DAYS * 86400000;

  await env.DB
    .prepare(`
      INSERT INTO sessions
      (user_id, token, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      Number(userId),
      rawToken,
      expiresAt,
      now()
    )
    .run();

  return rawToken;
}

async function signup(req, env) {
  const body = await readJSON(req);

  const username = clean(
    body.username,
    30
  );

  const email = clean(
    body.email,
    320
  ).toLowerCase();

  const password = String(
    body.password || ""
  );

  const displayName =
    clean(
      body.display_name ||
      body.displayName ||
      username,
      100
    );

  if (!usernameOK(username)) {
    throw new HttpError(
      400,
      "Invalid username"
    );
  }

  if (!emailOK(email)) {
    throw new HttpError(
      400,
      "Invalid email"
    );
  }

  if (password.length < 8) {
    throw new HttpError(
      400,
      "Password must be at least 8 characters"
    );
  }

  const existingUsername =
    await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE lower(username)=lower(?)
        LIMIT 1
      `)
      .bind(username)
      .first();

  if (existingUsername) {
    throw new HttpError(
      409,
      "Username already exists"
    );
  }

  const existingEmail =
    await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE lower(email)=lower(?)
        LIMIT 1
      `)
      .bind(email)
      .first();

  if (existingEmail) {
    throw new HttpError(
      409,
      "Email already exists"
    );
  }

  const passwordHash =
    await hashPassword(password);

  const userId =
    await insertUser(
      env,
      username,
      email,
      displayName,
      passwordHash
    );

  /*
    The live database has:
      password_salt TEXT DEFAULT ''
    The actual PBKDF2 salt is already contained
    inside password_hash, so password_salt stays
    empty for compatibility.
  */

  await ensureSettings(
    env,
    userId
  );

  const session =
    await createSession(
      env,
      userId
    );

  const user =
    await getUserById(
      env,
      userId
    );

  return json(
    {
      ok: true,
      user: ownUser(user)
    },
    201,
    {
      "Set-Cookie":
        setSession(session)
    }
  );
}

async function login(req, env) {
  const body =
    await readJSON(req);

  const identifier =
    clean(
      body.identifier ||
      body.username ||
      body.email,
      320
    );

  const password =
    String(
      body.password || ""
    );

  if (!identifier || !password) {
    throw new HttpError(
      400,
      "Username/email and password are required"
    );
  }

  const user =
    await findUser(
      env,
      identifier
    );

  if (!user) {
    throw new HttpError(
      401,
      "Invalid user or password"
    );
  }

  const valid =
    await verifyPassword(
      password,
      user.password_hash
    );

  /*
    Existing accounts created by the old system
    may use the old password_hash/password_salt
    format.

    We don't pretend those hashes are compatible.
    They should use password reset if verification
    fails.
  */

  if (!valid) {
    throw new HttpError(
      401,
      "Invalid user or password"
    );
  }

  const session =
    await createSession(
      env,
      user.id
    );

  await ensureSettings(
    env,
    user.id
  );

  return json(
    {
      ok: true,
      user: ownUser(user)
    },
    200,
    {
      "Set-Cookie":
        setSession(session)
    }
  );
}

async function logout(req, env) {
  const session =
    getCookie(
      req,
      "zilnet_session"
    );

  if (session) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token=?
      `)
      .bind(session)
      .run();
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie":
        clearSession()
    }
  );
}

async function me(req, env) {
  const user =
    await requireUser(
      req,
      env
    );

  await ensureSettings(
    env,
    user.id
  );

  return json({
    ok: true,
    user: ownUser(user)
  });
}

async function updateProfile(
  req,
  env,
  user
) {
  const body =
    await readJSON(req);

  const displayName =
    clean(
      body.display_name ??
      body.displayName ??
      user.display_name,
      100
    );

  const bio =
    clean(
      body.bio ??
      user.bio ??
      "",
      1000
    );

  const skills =
    clean(
      body.skills ??
      user.skills ??
      "",
      2000
    );

  const avatar =
    clean(
      body.avatar_url ??
      body.avatarUrl ??
      user.avatar_url ??
      "",
      2000
    );

  await env.DB
    .prepare(`
      UPDATE users
      SET
        display_name=?,
        bio=?,
        skills=?,
        avatar_url=?
      WHERE id=?
    `)
    .bind(
      displayName,
      bio,
      skills,
      avatar,
      Number(user.id)
    )
    .run();

  const updated =
    await getUserById(
      env,
      user.id
    );

  return json({
    ok: true,
    user: ownUser(updated)
  });
}

async function changePassword(
  req,
  env,
  user
) {
  const body =
    await readJSON(req);

  const current =
    String(
      body.current_password ||
      body.currentPassword ||
      ""
    );

  const next =
    String(
      body.new_password ||
      body.newPassword ||
      ""
    );

  if (!current || !next) {
    throw new HttpError(
      400,
      "Both passwords are required"
    );
  }

  if (next.length < 8) {
    throw new HttpError(
      400,
      "New password must be at least 8 characters"
    );
  }

  const valid =
    await verifyPassword(
      current,
      user.password_hash
    );

  if (!valid) {
    throw new HttpError(
      401,
      "Current password is incorrect"
    );
  }

  const passwordHash =
    await hashPassword(next);

  await env.DB
    .prepare(`
      UPDATE users
      SET
        password_hash=?,
        password_salt=''
      WHERE id=?
    `)
    .bind(
      passwordHash,
      Number(user.id)
    )
    .run();

  /*
    Invalidate every existing session after
    changing the password.
  */

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE user_id=?
    `)
    .bind(
      Number(user.id)
    )
    .run();

  const session =
    await createSession(
      env,
      user.id
    );

  return json(
    {
      ok: true,
      message:
        "Password changed successfully"
    },
    200,
    {
      "Set-Cookie":
        setSession(session)
    }
  );
}

async function followUser(
  req,
  env,
  user,
  targetUsername
) {
  const target =
    await env.DB
      .prepare(`
        SELECT *
        FROM users
        WHERE lower(username)=lower(?)
        LIMIT 1
      `)
      .bind(targetUsername)
      .first();

  if (!target) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  if (
    Number(target.id) ===
    Number(user.id)
  ) {
    throw new HttpError(
      400,
      "You cannot follow yourself"
    );
  }

  await env.DB
    .prepare(`
      INSERT OR IGNORE INTO follows
      (follower_id, following_id, created_at)
      VALUES (?, ?, ?)
    `)
    .bind(
      Number(user.id),
      Number(target.id),
      now()
    )
    .run();

  await notify(
    env,
    target.id,
    user.id,
    "follow",
    null
  );

  return json({
    ok: true,
    following: true
  });
}

async function unfollowUser(
  req,
  env,
  user,
  targetUsername
) {
  const target =
    await env.DB
      .prepare(`
        SELECT id
        FROM users
        WHERE lower(username)=lower(?)
        LIMIT 1
      `)
      .bind(targetUsername)
      .first();

  if (!target) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  await env.DB
    .prepare(`
      DELETE FROM follows
      WHERE follower_id=?
        AND following_id=?
    `)
    .bind(
      Number(user.id),
      Number(target.id)
    )
    .run();

  return json({
    ok: true,
    following: false
  });
}

async function feed(
  req,
  env,
  user
) {
  const url =
    new URL(req.url);

  const limit =
    Math.min(
      Number(
        url.searchParams.get(
          "limit"
        ) || 50
      ),
      100
    );

  const result =
    await env.DB
      .prepare(`
        SELECT
          p.*,
          u.username,
          u.display_name,
          u.avatar_url,
          (
            SELECT COUNT(*)
            FROM likes l
            WHERE l.post_id=p.id
          ) AS likes_count,
          (
            SELECT COUNT(*)
            FROM comments c
            WHERE c.post_id=p.id
          ) AS comments_count,
          CASE
            WHEN EXISTS (
              SELECT 1
              FROM likes l2
              WHERE l2.post_id=p.id
                AND l2.user_id=?
            )
            THEN 1
            ELSE 0
          END AS liked,
          CASE
            WHEN EXISTS (
              SELECT 1
              FROM saved_posts sp
              WHERE sp.post_id=p.id
                AND sp.user_id=?
            )
            THEN 1
            ELSE 0
          END AS saved
        FROM posts p
        JOIN users u
          ON u.id=p.user_id
        WHERE
          p.visibility='public'
          OR p.user_id=?
          OR EXISTS (
            SELECT 1
            FROM follows f
            WHERE f.follower_id=?
              AND f.following_id=p.user_id
          )
        ORDER BY p.id DESC
        LIMIT ?
      `)
      .bind(
        Number(user.id),
        Number(user.id),
        Number(user.id),
        Number(user.id),
        limit
      )
      .all();

  return json({
    ok: true,
    posts:
      result.results || []
  });
}

async function searchUsers(
  req,
  env
) {
  const url =
    new URL(req.url);

  const q =
    clean(
      url.searchParams.get(
        "q"
      ) || "",
      100
    );

  if (!q) {
    return json({
      ok: true,
      users: []
    });
  }

  const result =
    await env.DB
      .prepare(`
        SELECT
          id,
          username,
          display_name,
          bio,
          avatar_url,
          skills
        FROM users
        WHERE
          lower(username)
            LIKE lower(?)
          OR lower(display_name)
            LIKE lower(?)
        ORDER BY username
        LIMIT 50
      `)
      .bind(
        `%${q}%`,
        `%${q}%`
      )
      .all();

  return json({
    ok: true,
    users:
      (result.results || [])
        .map(publicUser)
  });
}

async function createPost(
  req,
  env,
  user
) {
  const body =
    await readJSON(req);

  const content =
    clean(
      body.content,
      10000
    );

  const mediaUrl =
    clean(
      body.media_url ??
      body.mediaUrl ??
      "",
      4000
    );

  const mediaType =
    clean(
      body.media_type ??
      body.mediaType ??
      "",
      50
    );

  const visibility =
    clean(
      body.visibility ||
      "public",
      30
    );

  if (
    !content &&
    !mediaUrl
  ) {
    throw new HttpError(
      400,
      "Post cannot be empty"
    );
  }

  if (
    ![
      "public",
      "followers",
      "private"
    ].includes(visibility)
  ) {
    throw new HttpError(
      400,
      "Invalid visibility"
    );
  }

  const postId =
    crypto.randomUUID();

  await env.DB
    .prepare(`
      INSERT INTO posts
      (
        id,
        user_id,
        content,
        media_url,
        media_type,
        visibility,
        created_at
      )
      VALUES (?,?,?,?,?,?,?)
    `)
    .bind(
      postId,
      Number(user.id),
      content,
      mediaUrl,
      mediaType,
      visibility,
      now()
    )
    .run();

  return json({
    ok: true,
    id: postId
  }, 201);
}

async function getPost(
  req,
  env,
  user,
  postId
) {
  const post =
    await env.DB
      .prepare(`
        SELECT
          p.*,
          u.username,
          u.display_name,
          u.avatar_url,
          (
            SELECT COUNT(*)
            FROM likes l
            WHERE l.post_id=p.id
          ) AS likes_count,
          (
            SELECT COUNT(*)
            FROM comments c
            WHERE c.post_id=p.id
          ) AS comments_count
        FROM posts p
        JOIN users u
          ON u.id=p.user_id
        WHERE p.id=?
        LIMIT 1
      `)
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  return json({
    ok: true,
    post
  });
}

async function deletePost(
  req,
  env,
  user,
  postId
) {
  const post =
    await env.DB
      .prepare(`
        SELECT *
        FROM posts
        WHERE id=?
        LIMIT 1
      `)
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  if (
    Number(post.user_id) !==
    Number(user.id)
  ) {
    throw new HttpError(
      403,
      "You can only delete your own posts"
    );
  }

  await env.DB
    .prepare(`
      DELETE FROM posts
      WHERE id=?
    `)
    .bind(postId)
    .run();

  return json({
    ok: true
  });
}

async function likePost(
  req,
  env,
  user,
  postId
) {
  const post =
    await env.DB
      .prepare(`
        SELECT user_id
        FROM posts
        WHERE id=?
        LIMIT 1
      `)
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT 1
        FROM likes
        WHERE post_id=?
          AND user_id=?
        LIMIT 1
      `)
      .bind(
        postId,
        Number(user.id)
      )
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        DELETE FROM likes
        WHERE post_id=?
          AND user_id=?
      `)
      .bind(
        postId,
        Number(user.id)
      )
      .run();

    return json({
      ok: true,
      liked: false
    });
  }

  await env.DB
    .prepare(`
      INSERT INTO likes
      (post_id, user_id, created_at)
      VALUES (?, ?, ?)
    `)
    .bind(
      postId,
      Number(user.id),
      now()
    )
    .run();

  await notify(
    env,
    post.user_id,
    user.id,
    "like",
    postId
  );

  return json({
    ok: true,
    liked: true
  });
}
async function savePost(
  req,
  env,
  user,
  postId
) {
  const existing =
    await env.DB
      .prepare(`
        SELECT 1
        FROM saved_posts
        WHERE post_id=?
          AND user_id=?
        LIMIT 1
      `)
      .bind(
        postId,
        Number(user.id)
      )
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        DELETE FROM saved_posts
        WHERE post_id=?
          AND user_id=?
      `)
      .bind(
        postId,
        Number(user.id)
      )
      .run();

    return json({
      ok: true,
      saved: false
    });
  }

  await env.DB
    .prepare(`
      INSERT INTO saved_posts
      (post_id, user_id, created_at)
      VALUES (?, ?, ?)
    `)
    .bind(
      postId,
      Number(user.id),
      now()
    )
    .run();

  return json({
    ok: true,
    saved: true
  });
}

async function comments(
  req,
  env,
  user,
  postId
) {
  const method =
    req.method.toUpperCase();

  if (method === "GET") {
    const result =
      await env.DB
        .prepare(`
          SELECT
            c.*,
            u.username,
            u.display_name,
            u.avatar_url
          FROM comments c
          JOIN users u
            ON u.id=c.user_id
          WHERE c.post_id=?
          ORDER BY c.id ASC
          LIMIT 200
        `)
        .bind(postId)
        .all();

    return json({
      ok: true,
      comments:
        result.results || []
    });
  }

  const body =
    await readJSON(req);

  const content =
    clean(
      body.content,
      2000
    );

  if (!content) {
    throw new HttpError(
      400,
      "Comment cannot be empty"
    );
  }

  const post =
    await env.DB
      .prepare(`
        SELECT user_id
        FROM posts
        WHERE id=?
        LIMIT 1
      `)
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  const commentId =
    crypto.randomUUID();

  await env.DB
    .prepare(`
      INSERT INTO comments
      (
        id,
        post_id,
        user_id,
        content,
        created_at
      )
      VALUES (?,?,?,?,?)
    `)
    .bind(
      commentId,
      postId,
      Number(user.id),
      content,
      now()
    )
    .run();

  await notify(
    env,
    post.user_id,
    user.id,
    "comment",
    postId
  );

  return json({
    ok: true,
    id: commentId
  }, 201);
}

async function createStory(
  req,
  env,
  user
) {
  const body =
    await readJSON(req);

  const text =
    clean(
      body.text,
      5000
    );

  const mediaUrl =
    clean(
      body.media_url ??
      body.mediaUrl ??
      "",
      4000
    );

  if (!text && !mediaUrl) {
    throw new HttpError(
      400,
      "Story cannot be empty"
    );
  }

  const storyId =
    crypto.randomUUID();

  const created =
    Date.now();

  const expires =
    created +
    24 * 60 * 60 * 1000;

  await env.DB
    .prepare(`
      INSERT INTO stories
      (
        id,
        user_id,
        text,
        media_url,
        created_at,
        expires_at
      )
      VALUES (?,?,?,?,?,?)
    `)
    .bind(
      storyId,
      Number(user.id),
      text,
      mediaUrl,
      new Date(created).toISOString(),
      expires
    )
    .run();

  return json({
    ok: true,
    id: storyId
  }, 201);
}

async function stories(
  req,
  env,
  user
) {
  const result =
    await env.DB
      .prepare(`
        SELECT
          s.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM stories s
        JOIN users u
          ON u.id=s.user_id
        WHERE s.expires_at>?
        ORDER BY s.id DESC
        LIMIT 200
      `)
      .bind(Date.now())
      .all();

  return json({
    ok: true,
    stories:
      result.results || []
  });
}

async function createReel(
  req,
  env,
  user
) {
  const body =
    await readJSON(req);

  const videoUrl =
    clean(
      body.video_url ??
      body.videoUrl ??
      "",
      4000
    );

  const caption =
    clean(
      body.caption,
      5000
    );

  if (!videoUrl) {
    throw new HttpError(
      400,
      "Video is required"
    );
  }

  const reelId =
    crypto.randomUUID();

  await env.DB
    .prepare(`
      INSERT INTO reels
      (
        id,
        user_id,
        video_url,
        caption,
        created_at
      )
      VALUES (?,?,?,?,?)
    `)
    .bind(
      reelId,
      Number(user.id),
      videoUrl,
      caption,
      now()
    )
    .run();

  return json({
    ok: true,
    id: reelId
  }, 201);
}

async function getReels(
  req,
  env
) {
  const result =
    await env.DB
      .prepare(`
        SELECT
          r.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM reels r
        JOIN users u
          ON u.id=r.user_id
        ORDER BY r.id DESC
        LIMIT 100
      `)
      .all();

  return json({
    ok: true,
    reels:
      result.results || []
  });
}

async function getNotifications(
  req,
  env,
  user
) {
  const result =
    await env.DB
      .prepare(`
        SELECT
          n.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM notifications n
        JOIN users u
          ON u.id=n.actor_id
        WHERE n.user_id=?
        ORDER BY n.id DESC
        LIMIT 100
      `)
      .bind(
        Number(user.id)
      )
      .all();

  await env.DB
    .prepare(`
      UPDATE notifications
      SET is_read=1
      WHERE user_id=?
    `)
    .bind(
      Number(user.id)
    )
    .run();

  return json({
    ok: true,
    notifications:
      result.results || []
  });
}

async function settingsGet(
  req,
  env,
  user
) {
  const settings =
    await ensureSettings(
      env,
      user.id
    );

  return json({
    ok: true,
    settings
  });
}

async function settingsUpdate(
  req,
  env,
  user
) {
  const body =
    await readJSON(req);

  const current =
    await ensureSettings(
      env,
      user.id
    );

  const theme =
    clean(
      body.theme ??
      current.theme ??
      "system",
      30
    );

  const profileVisibility =
    clean(
      body.profile_visibility ??
      body.profileVisibility ??
      current.profile_visibility ??
      "public",
      30
    );

  const messagePrivacy =
    clean(
      body.message_privacy ??
      body.messagePrivacy ??
      current.message_privacy ??
      "everyone",
      30
    );

  let notificationSettings =
    current.notification_settings ||
    {};

  if (
    body.notification_settings !==
    undefined
  ) {
    notificationSettings =
      body.notification_settings;
  }

  await env.DB
    .prepare(`
      UPDATE user_settings
      SET
        theme=?,
        profile_visibility=?,
        message_privacy=?,
        notification_settings=?
      WHERE user_id=?
    `)
    .bind(
      theme,
      profileVisibility,
      messagePrivacy,
      JSON.stringify(
        notificationSettings
      ),
      String(user.id)
    )
    .run();

  return json({
    ok: true,
    settings:
      await ensureSettings(
        env,
        user.id
      )
  });
}

async function createChat(
  req,
  env,
  user
) {
  const body =
    await readJSON(req);

  const memberIds =
    Array.isArray(
      body.user_ids ||
      body.userIds
    )
      ? (
          body.user_ids ||
          body.userIds
        )
      : [];

  const uniqueIds =
    [
      Number(user.id),
      ...memberIds
        .map(Number)
        .filter(
          Number.isFinite
        )
    ].filter(
      (value, index, arr) =>
        arr.indexOf(value) ===
        index
    );

  if (
    uniqueIds.length < 2
  ) {
    throw new HttpError(
      400,
      "At least two members are required"
    );
  }

  const type =
    clean(
      body.type || "direct",
      30
    );

  const name =
    clean(
      body.name || "",
      100
    );

  const chatId =
    crypto.randomUUID();

  await env.DB
    .prepare(`
      INSERT INTO chats
      (id, type, name, created_at)
      VALUES (?,?,?,?)
    `)
    .bind(
      chatId,
      type,
      name,
      now()
    )
    .run();

  for (const memberId of uniqueIds) {
    await env.DB
      .prepare(`
        INSERT INTO chat_members
        (chat_id, user_id, joined_at)
        VALUES (?,?,?)
      `)
      .bind(
        chatId,
        memberId,
        now()
      )
      .run();
  }

  return json({
    ok: true,
    id: chatId
  }, 201);
}

async function chatList(
  req,
  env,
  user
) {
  const result =
    await env.DB
      .prepare(`
        SELECT
          c.id,
          c.type,
          c.name,
          c.created_at
        FROM chats c
        JOIN chat_members cm
          ON cm.chat_id=c.id
        WHERE cm.user_id=?
        ORDER BY c.id DESC
      `)
      .bind(
        Number(user.id)
      )
      .all();

  return json({
    ok: true,
    chats:
      result.results || []
  });
}

async function chatInfo(
  env,
  user,
  chatId
) {
  const chat =
    await env.DB
      .prepare(`
        SELECT
          c.*
        FROM chats c
        JOIN chat_members cm
          ON cm.chat_id=c.id
        WHERE c.id=?
          AND cm.user_id=?
        LIMIT 1
      `)
      .bind(
        chatId,
        Number(user.id)
      )
      .first();

  if (!chat) {
    throw new HttpError(
      404,
      "Chat not found"
    );
  }

  const members =
    await env.DB
      .prepare(`
        SELECT
          u.id,
          u.username,
          u.display_name,
          u.avatar_url
        FROM chat_members cm
        JOIN users u
          ON u.id=cm.user_id
        WHERE cm.chat_id=?
        ORDER BY cm.joined_at ASC
      `)
      .bind(chatId)
      .all();

  const messages =
    await env.DB
      .prepare(`
        SELECT
          m.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM messages m
        JOIN users u
          ON u.id=m.user_id
        WHERE m.chat_id=?
        ORDER BY m.id ASC
        LIMIT 500
      `)
      .bind(chatId)
      .all();

  return {
    ...chat,
    members:
      members.results || [],
    messages:
      messages.results || []
  };
}

async function chatMessages(
  req,
  env,
  user,
  chatId
) {
  const member =
    await env.DB
      .prepare(`
        SELECT 1
        FROM chat_members
        WHERE chat_id=?
          AND user_id=?
        LIMIT 1
      `)
      .bind(
        chatId,
        Number(user.id)
      )
      .first();

  if (!member) {
    throw new HttpError(
      403,
      "You are not a member of this chat"
    );
  }

  if (
    req.method.toUpperCase() ===
    "GET"
  ) {
    const result =
      await env.DB
        .prepare(`
          SELECT
            m.*,
            u.username,
            u.display_name,
            u.avatar_url
          FROM messages m
          JOIN users u
            ON u.id=m.user_id
          WHERE m.chat_id=?
          ORDER BY m.id ASC
          LIMIT 500
        `)
        .bind(chatId)
        .all();

    return json({
      ok: true,
      messages:
        result.results || []
    });
  }

  const body =
    await readJSON(req);

  const content =
    clean(
      body.content,
      10000
    );

  const mediaUrl =
    clean(
      body.media_url ??
      body.mediaUrl ??
      "",
      4000
    );

  if (
    !content &&
    !mediaUrl
  ) {
    throw new HttpError(
      400,
      "Message cannot be empty"
    );
  }

  const messageId =
    crypto.randomUUID();

  await env.DB
    .prepare(`
      INSERT INTO messages
      (
        id,
        chat_id,
        user_id,
        content,
        media_url,
        created_at
      )
      VALUES (?,?,?,?,?,?)
    `)
    .bind(
      messageId,
      chatId,
      Number(user.id),
      content,
      mediaUrl,
      now()
    )
    .run();

  return json({
    ok: true,
    id: messageId
  }, 201);
}

async function publicProfile(
  req,
  env,
  username
) {
  return json(
    await getProfile(
      env,
      null,
      username
    )
  );
}

async function route(
  req,
  env
) {
  const url =
    new URL(req.url);

  const path =
    url.pathname.replace(
      /\/+$/,
      ""
    ) || "/";

  const method =
    req.method.toUpperCase();

  /*
    Public profile lookup.
  */
  const profileMatch =
    path.match(
      /^\/api\/profile\/([^/]+)$/
    );

  if (
    profileMatch &&
    method === "GET"
  ) {
    return publicProfile(
      req,
      env,
      decodeURIComponent(
        profileMatch[1]
      )
    );
  }

  if (
    path === "/api/signup" &&
    method === "POST"
  ) {
    return signup(
      req,
      env
    );
  }

  if (
    path === "/api/login" &&
    method === "POST"
  ) {
    return login(
      req,
      env
    );
  }

  if (
    path === "/api/logout" &&
    method === "POST"
  ) {
    return logout(
      req,
      env
    );
  }

  if (
    path === "/api/me" &&
    method === "GET"
  ) {
    return me(
      req,
      env
    );
  }

  const user =
    await requireUser(
      req,
      env
    );

  if (
    path === "/api/profile/update" &&
    method === "POST"
  ) {
    return updateProfile(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/password" &&
    method === "POST"
  ) {
    return changePassword(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/feed" &&
    method === "GET"
  ) {
    return feed(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/search" &&
    method === "GET"
  ) {
    return searchUsers(
      req,
      env
    );
  }

  if (
    path === "/api/posts" &&
    method === "POST"
  ) {
    return createPost(
      req,
      env,
      user
    );
  }

  const postMatch =
    path.match(
      /^\/api\/posts\/([^/]+)$/
    );

  if (
    postMatch &&
    method === "GET"
  ) {
    return getPost(
      req,
      env,
      user,
      decodeURIComponent(
        postMatch[1]
      )
    );
  }

  if (
    postMatch &&
    method === "DELETE"
  ) {
    return deletePost(
      req,
      env,
      user,
      decodeURIComponent(
        postMatch[1]
      )
    );
  }

  const likeMatch =
    path.match(
      /^\/api\/posts\/([^/]+)\/like$/
    );

  if (
    likeMatch &&
    method === "POST"
  ) {
    return likePost(
      req,
      env,
      user,
      decodeURIComponent(
        likeMatch[1]
      )
    );
  }

  const saveMatch =
    path.match(
      /^\/api\/posts\/([^/]+)\/save$/
    );

  if (
    saveMatch &&
    method === "POST"
  ) {
    return savePost(
      req,
      env,
      user,
      decodeURIComponent(
        saveMatch[1]
      )
    );
  }

  const commentMatch =
    path.match(
      /^\/api\/posts\/([^/]+)\/comments$/
    );

  if (
    commentMatch &&
    (
      method === "GET" ||
      method === "POST"
    )
  ) {
    return comments(
      req,
      env,
      user,
      decodeURIComponent(
        commentMatch[1]
      )
    );
  }

  if (
    path === "/api/stories" &&
    method === "GET"
  ) {
    return stories(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/stories" &&
    method === "POST"
  ) {
    return createStory(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/reels" &&
    method === "GET"
  ) {
    return getReels(
      req,
      env
    );
  }

  if (
    path === "/api/reels" &&
    method === "POST"
  ) {
    return createReel(
      req,
      env,
      user
    );
  }

  const followMatch =
    path.match(
      /^\/api\/follow\/([^/]+)$/
    );

  if (
    followMatch &&
    method === "POST"
  ) {
    return followUser(
      req,
      env,
      user,
      decodeURIComponent(
        followMatch[1]
      )
    );
  }

  if (
    followMatch &&
    method === "DELETE"
  ) {
    return unfollowUser(
      req,
      env,
      user,
      decodeURIComponent(
        followMatch[1]
      )
    );
  }

  if (
    path === "/api/notifications" &&
    method === "GET"
  ) {
    return getNotifications(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/settings" &&
    method === "GET"
  ) {
    return settingsGet(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/settings" &&
    method === "POST"
  ) {
    return settingsUpdate(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/chats" &&
    method === "GET"
  ) {
    return chatList(
      req,
      env,
      user
    );
  }

  if (
    path === "/api/chats" &&
    method === "POST"
  ) {
    return createChat(
      req,
      env,
      user
    );
  }

  const chatMatch =
    path.match(
      /^\/api\/chats\/([^/]+)$/
    );

  if (
    chatMatch &&
    method === "GET"
  ) {
    return json({
      ok: true,
      chat:
        await chatInfo(
          env,
          user,
          decodeURIComponent(
            chatMatch[1]
          )
        )
    });
  }

  const chatMessagesMatch =
    path.match(
      /^\/api\/chats\/([^/]+)\/messages$/
    );

  if (
    chatMessagesMatch &&
    (
      method === "GET" ||
      method === "POST"
    )
  ) {
    return chatMessages(
      req,
      env,
      user,
      decodeURIComponent(
        chatMessagesMatch[1]
      )
    );
  }

  return error(
    404,
    "API route not found"
  );
}

export default {
  async fetch(req, env) {
    try {
      if (
        req.method.toUpperCase() ===
        "OPTIONS"
      ) {
        return new Response(
          null,
          {
            status: 204,
            headers: {
              "Access-Control-Allow-Origin":
                req.headers.get(
                  "Origin"
                ) || "*",
              "Access-Control-Allow-Methods":
                "GET,POST,PUT,DELETE,OPTIONS",
              "Access-Control-Allow-Headers":
                "Content-Type, Authorization",
              "Access-Control-Allow-Credentials":
                "true"
            }
          }
        );
      }

      const response =
        await route(
          req,
          env
        );

      const headers =
        new Headers(
          response.headers
        );

      headers.set(
        "Access-Control-Allow-Origin",
        req.headers.get(
          "Origin"
        ) || "*"
      );

      headers.set(
        "Access-Control-Allow-Credentials",
        "true"
      );

      return new Response(
        response.body,
        {
          status:
            response.status,
          statusText:
            response.statusText,
          headers
        }
      );
    } catch (err) {
      console.error(
        "ZILNET WORKER ERROR:",
        err
      );

      if (
        err instanceof HttpError
      ) {
        return error(
          err.status,
          err.message
        );
      }

      return error(
        500,
        "Internal server error"
      );
    }
  }
};
