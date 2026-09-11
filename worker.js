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
