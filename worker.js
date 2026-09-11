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
