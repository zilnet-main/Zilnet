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

function randomToken(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);

  return btoa(String.fromCharCode(...a))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
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

async function hashPassword(
  password,
  salt = randomToken(16),
  iterations = 120000
) {
  const normalized = salt
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(
      Math.ceil(salt.length / 4) * 4,
      "="
    );

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
  const p = String(stored || "").split("$");

  if (
    p.length !== 5 ||
    p[0] !== "pbkdf2" ||
    p[1] !== "sha256"
  ) {
    return false;
  }

  const iterations = Number(p[2]);

  if (
    !Number.isInteger(iterations) ||
    iterations < 10000 ||
    iterations > 1000000
  ) {
    return false;
  }

  const check = await hashPassword(
    password,
    p[3],
    iterations
  );

  return check === stored;
}

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

function sessionCookie(token) {
  return [
    `zilnet_session=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_DAYS * 86400}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "zilnet_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

function publicUser(u) {
  if (!u) return null;

  return {
    id: Number(u.id),
    username: u.username || "",
    display_name: u.display_name || "",
    bio: u.bio || "",
    avatar_url: u.avatar_url || "",
    skills: u.skills || "",
    created_at: u.created_at || ""
  };
}

function ownUser(u) {
  if (!u) return null;

  return {
    ...publicUser(u),
    email: u.email || ""
  };
}

function parseJSON(value, fallback = {}) {
  try {
    return JSON.parse(value || "{}");
  } catch {
    return fallback;
  }
}

async function requireUser(req, env) {
  const token = getCookie(
    req,
    "zilnet_session"
  );

  if (!token) {
    throw new HttpError(
      401,
      "Login required"
    );
  }

  const u = await env.DB
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
      token,
      Date.now()
    )
    .first();

  if (!u) {
    throw new HttpError(
      401,
      "Session expired"
    );
  }

  return u;
}

async function settingsFor(env, userId) {
  let s = await env.DB
    .prepare(`
      SELECT *
      FROM user_settings
      WHERE user_id=?
    `)
    .bind(String(userId))
    .first();

  if (!s) {
    await env.DB
      .prepare(`
        INSERT OR IGNORE INTO user_settings
        (user_id)
        VALUES (?)
      `)
      .bind(String(userId))
      .run();

    s = await env.DB
      .prepare(`
        SELECT *
        FROM user_settings
        WHERE user_id=?
      `)
      .bind(String(userId))
      .first();
  }

  return {
    ...s,
    notification_settings:
      parseJSON(
        s?.notification_settings,
        {}
      )
  };
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

  const s = await settingsFor(
    env,
    userId
  );

  const map = {
    like: "likes",
    comment: "comments",
    follow: "follows",
    message: "messages"
  };

  const setting =
    map[type];

  if (
    setting &&
    s.notification_settings?.[setting] === false
  ) {
    return;
  }

  await env.DB
    .prepare(`
      INSERT INTO notifications
      (
        user_id,
        actor_id,
        type,
        post_id
      )
      VALUES (?,?,?,?)
    `)
    .bind(
      Number(userId),
      Number(actorId),
      type,
      postId
    )
    .run();
}

async function findUserByUsername(
  env,
  username
) {
  return await env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE lower(username)=lower(?)
      LIMIT 1
    `)
    .bind(username)
    .first();
}

async function getProfile(
  env,
  viewer,
  username
) {
  const u =
    await findUserByUsername(
      env,
      username
    );

  if (!u) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const s =
    await settingsFor(
      env,
      u.id
    );

  const own =
    viewer &&
    Number(viewer.id) ===
      Number(u.id);

  const following =
    viewer
      ? !!(
          await env.DB
            .prepare(`
              SELECT id
              FROM follows
              WHERE follower_id=?
                AND following_id=?
              LIMIT 1
            `)
            .bind(
              Number(viewer.id),
              Number(u.id)
            )
            .first()
        )
      : false;

  const followerCount =
    await env.DB
      .prepare(`
        SELECT COUNT(*) c
        FROM follows
        WHERE following_id=?
      `)
      .bind(Number(u.id))
      .first();

  const followingCount =
    await env.DB
      .prepare(`
        SELECT COUNT(*) c
        FROM follows
        WHERE follower_id=?
      `)
      .bind(Number(u.id))
      .first();

  const privateProfile =
    s.profile_visibility ===
      "private" &&
    !own &&
    !following;

  if (privateProfile) {
    return {
      user: {
        ...publicUser(u),
        followers_count:
          Number(
            followerCount?.c || 0
          ),
        following_count:
          Number(
            followingCount?.c || 0
          ),
        following
      },
      posts: [],
      private: true
    };
  }

  const posts =
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
          ) likes_count,

          (
            SELECT COUNT(*)
            FROM comments c
            WHERE c.post_id=p.id
          ) comments_count,

          EXISTS(
            SELECT 1
            FROM likes lx
            WHERE lx.post_id=p.id
              AND lx.user_id=?
          ) liked,

          EXISTS(
            SELECT 1
            FROM saved_posts sx
            WHERE sx.post_id=CAST(p.id AS TEXT)
              AND sx.user_id=?
          ) saved

        FROM posts p

        JOIN users u
          ON u.id=p.user_id

        WHERE p.user_id=?

        ORDER BY p.id DESC
      `)
      .bind(
        Number(viewer?.id || 0),
        String(viewer?.id || ""),
        Number(u.id)
      )
      .all();

  return {
    user: {
      ...publicUser(u),
      followers_count:
        Number(
          followerCount?.c || 0
        ),
      following_count:
        Number(
          followingCount?.c || 0
        ),
      following
    },

    posts:
      posts.results || []
  };
}

async function getFeed(
  env,
  user
) {
  const r =
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
          ) likes_count,

          (
            SELECT COUNT(*)
            FROM comments c
            WHERE c.post_id=p.id
          ) comments_count,

          EXISTS(
            SELECT 1
            FROM likes l2
            WHERE l2.post_id=p.id
              AND l2.user_id=?
          ) liked,

          EXISTS(
            SELECT 1
            FROM saved_posts s2
            WHERE s2.post_id=CAST(p.id AS TEXT)
              AND s2.user_id=?
          ) saved

        FROM posts p

        JOIN users u
          ON u.id=p.user_id

        ORDER BY p.id DESC

        LIMIT 100
      `)
      .bind(
        Number(user.id),
        String(user.id)
      )
      .all();

  return {
    posts:
      r.results || [],

    stories:
      await getStories(
        env,
        user
      )
  };
}

async function getStories(
  env,
  user
) {
  const r =
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

        WHERE datetime(s.created_at)
              > datetime('now','-24 hours')

          AND (
            s.user_id=?

            OR s.user_id IN (
              SELECT following_id
              FROM follows
              WHERE follower_id=?
            )
          )

        ORDER BY s.id DESC
      `)
      .bind(
        Number(user.id),
        Number(user.id)
      )
      .all();

  return r.results || [];
}

async function getReels(
  env
) {
  const r =
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

  return r.results || [];
}
async function chatInfo(
  env,
  user,
  chatId
) {
  const chat =
    await env.DB
      .prepare(`
        SELECT *
        FROM chats
        WHERE id=?
        LIMIT 1
      `)
      .bind(Number(chatId))
      .first();

  if (!chat) {
    throw new HttpError(
      404,
      "Chat not found"
    );
  }

  const member =
    await env.DB
      .prepare(`
        SELECT id
        FROM chat_members
        WHERE chat_id=?
          AND user_id=?
        LIMIT 1
      `)
      .bind(
        Number(chatId),
        Number(user.id)
      )
      .first();

  if (!member) {
    throw new HttpError(
      403,
      "Not a member of this chat"
    );
  }

  if (Number(chat.is_group) === 1) {
    return {
      id: Number(chat.id),
      name: chat.name || "Group",
      username: "",
      avatar_url: "",
      is_group: true,
      type: "group"
    };
  }

  const other =
    await env.DB
      .prepare(`
        SELECT u.*
        FROM chat_members cm

        JOIN users u
          ON u.id=cm.user_id

        WHERE cm.chat_id=?
          AND cm.user_id<>?

        LIMIT 1
      `)
      .bind(
        Number(chatId),
        Number(user.id)
      )
      .first();

  return {
    id: Number(chat.id),

    name:
      other?.display_name ||
      other?.username ||
      "Chat",

    username:
      other?.username || "",

    avatar_url:
      other?.avatar_url || "",

    user:
      publicUser(other),

    is_group: false,
    type: "direct"
  };
}

async function chatsForUser(
  env,
  user
) {
  const r =
    await env.DB
      .prepare(`
        SELECT
          c.id,
          c.name,
          c.is_group,
          c.created_at,

          (
            SELECT m.content
            FROM messages m
            WHERE m.chat_id=c.id
            ORDER BY m.id DESC
            LIMIT 1
          ) last_message,

          (
            SELECT m2.created_at
            FROM messages m2
            WHERE m2.chat_id=c.id
            ORDER BY m2.id DESC
            LIMIT 1
          ) last_message_at

        FROM chats c

        JOIN chat_members cm
          ON cm.chat_id=c.id
          AND cm.user_id=?

        ORDER BY
          COALESCE(
            last_message_at,
            c.created_at
          ) DESC
      `)
      .bind(Number(user.id))
      .all();

  const result = [];

  for (
    const row of
      r.results || []
  ) {
    const info =
      await chatInfo(
        env,
        user,
        row.id
      );

    result.push({
      ...info,
      last_message:
        row.last_message || "",
      last_message_at:
        row.last_message_at || ""
    });
  }

  return result;
}

async function createChat(
  env,
  user,
  targetId
) {
  targetId = Number(targetId);

  if (
    !targetId ||
    targetId === Number(user.id)
  ) {
    throw new HttpError(
      400,
      "Invalid user"
    );
  }

  const target =
    await env.DB
      .prepare(`
        SELECT *
        FROM users
        WHERE id=?
        LIMIT 1
      `)
      .bind(targetId)
      .first();

  if (!target) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const s =
    await settingsFor(
      env,
      targetId
    );

  if (
    s.message_privacy ===
    "nobody"
  ) {
    throw new HttpError(
      403,
      "This user does not accept messages"
    );
  }

  if (
    s.message_privacy ===
    "followers"
  ) {
    const following =
      await env.DB
        .prepare(`
          SELECT id
          FROM follows
          WHERE follower_id=?
            AND following_id=?
          LIMIT 1
        `)
        .bind(
          Number(user.id),
          targetId
        )
        .first();

    if (!following) {
      throw new HttpError(
        403,
        "Follow this user before messaging them"
      );
    }
  }

  const existing =
    await env.DB
      .prepare(`
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
      `)
      .bind(
        Number(user.id),
        targetId
      )
      .first();

  if (existing) {
    return await chatInfo(
      env,
      user,
      existing.id
    );
  }

  const r =
    await env.DB
      .prepare(`
        INSERT INTO chats
        (name,is_group)
        VALUES (?,0)
      `)
      .bind("")
      .run();

  const chatId =
    Number(r.meta.last_row_id);

  await env.DB.batch([
    env.DB
      .prepare(`
        INSERT INTO chat_members
        (chat_id,user_id)
        VALUES (?,?)
      `)
      .bind(
        chatId,
        Number(user.id)
      ),

    env.DB
      .prepare(`
        INSERT INTO chat_members
        (chat_id,user_id)
        VALUES (?,?)
      `)
      .bind(
        chatId,
        targetId
      )
  ]);

  return await chatInfo(
    env,
    user,
    chatId
  );
}

async function createGroup(
  env,
  user,
  body
) {
  const name =
    clean(body.name, 80) ||
    "New group";

  let ids =
    Array.isArray(body.user_ids)
      ? body.user_ids
          .map(Number)
          .filter(Boolean)
      : [];

  ids = [
    ...new Set(ids)
  ].filter(
    id =>
      id !== Number(user.id)
  );

  if (ids.length > 49) {
    throw new HttpError(
      400,
      "Maximum 50 group members"
    );
  }

  if (ids.length) {
    const marks =
      ids.map(() => "?").join(",");

    const users =
      await env.DB
        .prepare(`
          SELECT id
          FROM users
          WHERE id IN (${marks})
        `)
        .bind(...ids)
        .all();

    if (
      (users.results || []).length !==
      ids.length
    ) {
      throw new HttpError(
        400,
        "One or more users do not exist"
      );
    }
  }

  const r =
    await env.DB
      .prepare(`
        INSERT INTO chats
        (name,is_group)
        VALUES (?,1)
      `)
      .bind(name)
      .run();

  const chatId =
    Number(r.meta.last_row_id);

  const statements = [
    env.DB
      .prepare(`
        INSERT INTO chat_members
        (chat_id,user_id)
        VALUES (?,?)
      `)
      .bind(
        chatId,
        Number(user.id)
      )
  ];

  for (const id of ids) {
    statements.push(
      env.DB
        .prepare(`
          INSERT INTO chat_members
          (chat_id,user_id)
          VALUES (?,?)
        `)
        .bind(
          chatId,
          id
        )
    );
  }

  await env.DB.batch(
    statements
  );

  return await chatInfo(
    env,
    user,
    chatId
  );
}

async function sendMessage(
  env,
  user,
  chatId,
  content
) {
  const member =
    await env.DB
      .prepare(`
        SELECT id
        FROM chat_members
        WHERE chat_id=?
          AND user_id=?
        LIMIT 1
      `)
      .bind(
        Number(chatId),
        Number(user.id)
      )
      .first();

  if (!member) {
    throw new HttpError(
      403,
      "Not a chat member"
    );
  }

  const text =
    clean(content, 5000);

  if (!text) {
    throw new HttpError(
      400,
      "Message is empty"
    );
  }

  const r =
    await env.DB
      .prepare(`
        INSERT INTO messages
        (
          chat_id,
          user_id,
          content,
          media_url
        )
        VALUES (?,?,?,?)
      `)
      .bind(
        Number(chatId),
        Number(user.id),
        text,
        ""
      )
      .run();

  const message =
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

        WHERE m.id=?
      `)
      .bind(
        Number(r.meta.last_row_id)
      )
      .first();

  const members =
    await env.DB
      .prepare(`
        SELECT user_id
        FROM chat_members
        WHERE chat_id=?
          AND user_id<>?
      `)
      .bind(
        Number(chatId),
        Number(user.id)
      )
      .all();

  for (
    const m of
      members.results || []
  ) {
    await notify(
      env,
      m.user_id,
      user.id,
      "message"
    );
  }

  return message;
}

async function getMessages(
  env,
  user,
  chatId
) {
  const member =
    await env.DB
      .prepare(`
        SELECT id
        FROM chat_members
        WHERE chat_id=?
          AND user_id=?
        LIMIT 1
      `)
      .bind(
        Number(chatId),
        Number(user.id)
      )
      .first();

  if (!member) {
    throw new HttpError(
      403,
      "Not a chat member"
    );
  }

  const r =
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
      .bind(
        Number(chatId)
      )
      .all();

  return r.results || [];
}

async function uploadFile(
  env,
  user,
  req
) {
  if (!env.MEDIA) {
    throw new HttpError(
      503,
      "Media storage is not configured"
    );
  }

  const form =
    await req.formData();

  const file =
    form.get("file");

  if (!(file instanceof File)) {
    throw new HttpError(
      400,
      "Choose a file"
    );
  }

  if (
    file.size >
    50 * 1024 * 1024
  ) {
    throw new HttpError(
      413,
      "File is too large"
    );
  }

  const ext =
    (
      file.name.match(
        /\.[A-Za-z0-9]{1,10}$/
      ) || [""]
    )[0].toLowerCase();

  const key =
    `media/${user.id}/${Date.now()}-${randomToken(8)}${ext}`;

  await env.MEDIA.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType:
          file.type ||
          "application/octet-stream",

        cacheControl:
          "public,max-age=31536000"
      }
    }
  );

  return {
    url:
      `/media/${encodeURIComponent(key)}`,
    key
  };
}
async function route(
  req,
  env
) {
  const url =
    new URL(req.url);

  const path =
    url.pathname.replace(
      /\/$/,
      ""
    ) || "/";

  const method =
    req.method.toUpperCase();

  // =========================
  // SIGNUP
  // =========================

  if (
    path === "/api/signup" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const username =
      clean(b.username, 30);

    const email =
      clean(b.email, 200)
        .toLowerCase();

    const password =
      String(b.password || "");

    if (!usernameOK(username)) {
      throw new HttpError(
        400,
        "Username must be 3-30 characters"
      );
    }

    if (!emailOK(email)) {
      throw new HttpError(
        400,
        "Valid email is required"
      );
    }

    if (password.length < 8) {
      throw new HttpError(
        400,
        "Password must be at least 8 characters"
      );
    }

    const existsUser =
      await env.DB
        .prepare(`
          SELECT id
          FROM users
          WHERE lower(username)=lower(?)
          LIMIT 1
        `)
        .bind(username)
        .first();

    if (existsUser) {
      throw new HttpError(
        409,
        "Username already exists"
      );
    }

    const existsEmail =
      await env.DB
        .prepare(`
          SELECT id
          FROM users
          WHERE lower(email)=lower(?)
          LIMIT 1
        `)
        .bind(email)
        .first();

    if (existsEmail) {
      throw new HttpError(
        409,
        "Email already exists"
      );
    }

    const passwordHash =
      await hashPassword(
        password
      );

    const r =
      await env.DB
        .prepare(`
          INSERT INTO users
          (
            username,
            email,
            password_hash,
            display_name
          )
          VALUES (?,?,?,?)
        `)
        .bind(
          username,
          email,
          passwordHash,
          clean(
            b.display_name,
            80
          )
        )
        .run();

    const id =
      Number(r.meta.last_row_id);

    const token =
      randomToken();

    await env.DB
      .prepare(`
        INSERT INTO sessions
        (
          user_id,
          token,
          expires_at
        )
        VALUES (?,?,?)
      `)
      .bind(
        id,
        token,
        Date.now() +
          SESSION_DAYS * 86400000
      )
      .run();

    const u =
      await env.DB
        .prepare(
          "SELECT * FROM users WHERE id=?"
        )
        .bind(id)
        .first();

    return json(
      {
        user:
          ownUser(u)
      },
      200,
      {
        "Set-Cookie":
          sessionCookie(token)
      }
    );
  }

  // =========================
  // LOGIN
  // =========================

  if (
    path === "/api/login" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const identifier =
      clean(
        b.identifier ||
        b.username ||
        b.email,
        200
      ).toLowerCase();

    const password =
      String(b.password || "");

    const u =
      await env.DB
        .prepare(`
          SELECT *
          FROM users

          WHERE lower(username)=?
             OR lower(email)=?

          LIMIT 1
        `)
        .bind(
          identifier,
          identifier
        )
        .first();

    if (
      !u ||
      !(await verifyPassword(
        password,
        u.password_hash
      ))
    ) {
      throw new HttpError(
        401,
        "Invalid username/email or password"
      );
    }

    const token =
      randomToken();

    await env.DB
      .prepare(`
        INSERT INTO sessions
        (
          user_id,
          token,
          expires_at
        )
        VALUES (?,?,?)
      `)
      .bind(
        Number(u.id),
        token,
        Date.now() +
          SESSION_DAYS * 86400000
      )
      .run();

    return json(
      {
        user:
          ownUser(u)
      },
      200,
      {
        "Set-Cookie":
          sessionCookie(token)
      }
    );
  }

  // =========================
  // LOGOUT
  // =========================

  if (
    path === "/api/logout" &&
    method === "POST"
  ) {
    const token =
      getCookie(
        req,
        "zilnet_session"
      );

    if (token) {
      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE token=?
        `)
        .bind(token)
        .run();
    }

    return json(
      { ok: true },
      200,
      {
        "Set-Cookie":
          clearSessionCookie()
      }
    );
  }

  // =========================
  // ME
  // =========================

  if (
    path === "/api/me" &&
    method === "GET"
  ) {
    const user =
      await requireUser(
        req,
        env
      );

    return json({
      user:
        ownUser(user)
    });
  }

  // =========================
  // PASSWORD RESET REQUEST
  // Supports BOTH names
  // =========================

  if (
    (
      path === "/api/forgot-password" ||
      path === "/api/password-reset"
    ) &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const email =
      clean(b.email, 200)
        .toLowerCase();

    if (!emailOK(email)) {
      throw new HttpError(
        400,
        "Enter a valid email"
      );
    }

    const u =
      await env.DB
        .prepare(`
          SELECT id,email
          FROM users
          WHERE lower(email)=?
          LIMIT 1
        `)
        .bind(email)
        .first();

    const resetId =
      crypto.randomUUID();

    if (u) {
      const code =
        String(
          Math.floor(
            100000 +
            Math.random() * 900000
          )
        );

      const tokenHash =
        await sha256(code);

      await env.DB
        .prepare(`
          DELETE FROM password_resets
          WHERE user_id=?
        `)
        .bind(
          String(u.id)
        )
        .run();

      await env.DB
        .prepare(`
          INSERT INTO password_resets
          (
            id,
            user_id,
            token_hash,
            expires_at,
            created_at
          )
          VALUES (?,?,?,?,?)
        `)
        .bind(
          resetId,
          String(u.id),
          tokenHash,
          Date.now() +
            RESET_MINUTES * 60000,
          new Date().toISOString()
        )
        .run();

      if (
        env.RESEND_API_KEY &&
        env.RESET_FROM_EMAIL
      ) {
        const response =
          await fetch(
            "https://api.resend.com/emails",
            {
              method: "POST",

              headers: {
                Authorization:
                  `Bearer ${env.RESEND_API_KEY}`,
                "Content-Type":
                  "application/json"
              },

              body: JSON.stringify({
                from:
                  env.RESET_FROM_EMAIL,

                to: [email],

                subject:
                  "ZILNET password reset code",

                html: `
                  <h2>ZILNET password reset</h2>
                  <p>Your verification code is:</p>
                  <h1>${code}</h1>
                  <p>This code expires in ${RESET_MINUTES} minutes.</p>
                `
              })
            }
          );

        if (!response.ok) {
          throw new HttpError(
            502,
            "Could not send recovery email"
          );
        }
      }
    }

    return json({
      message:
        "If an account matches that email, a verification code has been sent.",
      reset_id: resetId
    });
  }

  // =========================
  // PASSWORD RESET
  // =========================

  if (
    path === "/api/reset-password" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const resetId =
      clean(b.reset_id, 100);

    const code =
      clean(b.code, 20);

    const newPassword =
      String(
        b.new_password ||
        b.password ||
        ""
      );

    if (
      !resetId ||
      !/^\d{6}$/.test(code) ||
      newPassword.length < 8
    ) {
      throw new HttpError(
        400,
        "Invalid reset details"
      );
    }

    const hash =
      await sha256(code);

    const reset =
      await env.DB
        .prepare(`
          SELECT *
          FROM password_resets

          WHERE id=?
            AND token_hash=?
            AND expires_at>?

          LIMIT 1
        `)
        .bind(
          resetId,
          hash,
          Date.now()
        )
        .first();

    if (!reset) {
      throw new HttpError(
        400,
        "Invalid or expired code"
      );
    }

    const passwordHash =
      await hashPassword(
        newPassword
      );

    await env.DB
      .prepare(`
        UPDATE users
        SET password_hash=?,
            password_salt=''
        WHERE id=?
      `)
      .bind(
        passwordHash,
        Number(reset.user_id)
      )
      .run();

    await env.DB
      .prepare(`
        DELETE FROM password_resets
        WHERE id=?
      `)
      .bind(resetId)
      .run();

    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE user_id=?
      `)
      .bind(
        Number(reset.user_id)
      )
      .run();

    const token =
      randomToken();

    await env.DB
      .prepare(`
        INSERT INTO sessions
        (
          user_id,
          token,
          expires_at
        )
        VALUES (?,?,?)
      `)
      .bind(
        Number(reset.user_id),
        token,
        Date.now() +
          SESSION_DAYS * 86400000
      )
      .run();

    const u =
      await env.DB
        .prepare(
          "SELECT * FROM users WHERE id=?"
        )
        .bind(
          Number(reset.user_id)
        )
        .first();

    return json(
      {
        ok: true,
        user:
          ownUser(u)
      },
      200,
      {
        "Set-Cookie":
          sessionCookie(token)
      }
    );
  }

  // =========================
  // MEDIA
  // =========================

  if (
    path.startsWith("/media/") &&
    method === "GET"
  ) {
    if (!env.MEDIA) {
      throw new HttpError(
        503,
        "Media storage is not configured"
      );
    }

    const key =
      decodeURIComponent(
        path.slice(7)
      );

    const object =
      await env.MEDIA.get(key);

    if (!object) {
      return new Response(
        "Not found",
        { status: 404 }
      );
    }

    const headers =
      new Headers();

    object.writeHttpMetadata(
      headers
    );

    headers.set(
      "etag",
      object.httpEtag
    );

    headers.set(
      "cache-control",
      "public,max-age=31536000"
    );

    return new Response(
      object.body,
      { headers }
    );
  }

  // Everything below requires login.

  const user =
    await requireUser(
      req,
      env
    );

  // =========================
  // PROFILE
  // =========================

  if (
    path === "/api/profile" &&
    method === "GET"
  ) {
    return json(
      await getProfile(
        env,
        user,
        user.username
      )
    );
  }

  if (
    path === "/api/profile/update" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    await env.DB
      .prepare(`
        UPDATE users

        SET display_name=?,
            bio=?,
            skills=?,
            avatar_url=?

        WHERE id=?
      `)
      .bind(
        clean(
          b.display_name,
          80
        ),

        clean(
          b.bio,
          500
        ),

        clean(
          b.skills,
          500
        ),

        clean(
          b.avatar_url,
          2000
        ),

        Number(user.id)
      )
      .run();

    const updated =
      await env.DB
        .prepare(
          "SELECT * FROM users WHERE id=?"
        )
        .bind(
          Number(user.id)
        )
        .first();

    return json({
      user:
        ownUser(updated)
    });
  }

  // Change password while logged in

  if (
    path === "/api/profile/password" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const current =
      String(
        b.current_password || ""
      );

    const next =
      String(
        b.new_password || ""
      );

    if (
      next.length < 8
    ) {
      throw new HttpError(
        400,
        "New password must be at least 8 characters"
      );
    }

    if (
      !(await verifyPassword(
        current,
        user.password_hash
      ))
    ) {
      throw new HttpError(
        401,
        "Current password is incorrect"
      );
    }

    const hash =
      await hashPassword(
        next
      );

    await env.DB
      .prepare(`
        UPDATE users
        SET password_hash=?,
            password_salt=''
        WHERE id=?
      `)
      .bind(
        hash,
        Number(user.id)
      )
      .run();

    return json({
      ok: true
    });
  }

  // Public profile routes

  const profileMatch =
    path.match(
      /^\/api\/(?:profile|users)\/([^/]+)$/
    );

  if (
    profileMatch &&
    method === "GET"
  ) {
    return json(
      await getProfile(
        env,
        user,
        decodeURIComponent(
          profileMatch[1]
        )
      )
    );
  }

  // =========================
  // FOLLOW
  // =========================

  const followMatch =
    path.match(
      /^\/api\/users\/(\d+)\/follow$/
    );

  if (
    followMatch &&
    method === "POST"
  ) {
    const target =
      Number(
        followMatch[1]
      );

    if (
      target === Number(user.id)
    ) {
      throw new HttpError(
        400,
        "You cannot follow yourself"
      );
    }

    const targetUser =
      await env.DB
        .prepare(
          "SELECT id FROM users WHERE id=?"
        )
        .bind(target)
        .first();

    if (!targetUser) {
      throw new HttpError(
        404,
        "User not found"
      );
    }

    const existing =
      await env.DB
        .prepare(`
          SELECT id
          FROM follows
          WHERE follower_id=?
            AND following_id=?
          LIMIT 1
        `)
        .bind(
          Number(user.id),
          target
        )
        .first();

    if (existing) {
      await env.DB
        .prepare(
          "DELETE FROM follows WHERE id=?"
        )
        .bind(existing.id)
        .run();

      return json({
        following: false
      });
    }

    await env.DB
      .prepare(`
        INSERT INTO follows
        (
          follower_id,
          following_id
        )
        VALUES (?,?)
      `)
      .bind(
        Number(user.id),
        target
      )
      .run();

    await notify(
      env,
      target,
      user.id,
      "follow"
    );

    return json({
      following: true
    });
  }

  // =========================
  // SEARCH
  // =========================

  if (
    path === "/api/search" &&
    method === "GET"
  ) {
    const q =
      clean(
        url.searchParams.get("q"),
        100
      );

    const pattern =
      `%${q}%`;

    const r =
      await env.DB
        .prepare(`
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

            AND (
              lower(u.username)
                LIKE lower(?)

              OR lower(u.display_name)
                LIKE lower(?)

              OR lower(u.skills)
                LIKE lower(?)
            )

          ORDER BY u.id DESC

          LIMIT 50
        `)
        .bind(
          Number(user.id),
          Number(user.id),
          pattern,
          pattern,
          pattern
        )
        .all();

    return json({
      users:
        r.results || []
    });
  }

  // =========================
  // FEED
  // =========================

  if (
    path === "/api/feed" &&
    method === "GET"
  ) {
    return json(
      await getFeed(
        env,
        user
      )
    );
  }

  // =========================
  // POSTS
  // =========================

  if (
    path === "/api/posts" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const content =
      clean(b.content, 10000);

    const media =
      clean(b.media_url, 2000);

    const mediaType =
      clean(
        b.media_type,
        100
      );

    if (
      !content &&
      !media
    ) {
      throw new HttpError(
        400,
        "Post needs text or media"
      );
    }

    const r =
      await env.DB
        .prepare(`
          INSERT INTO posts
          (
            user_id,
            content,
            media_url,
            media_type
          )
          VALUES (?,?,?,?)
        `)
        .bind(
          Number(user.id),
          content,
          media,
          mediaType
        )
        .run();

    const id =
      Number(r.meta.last_row_id);

    const post =
      await env.DB
        .prepare(`
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

          JOIN users u
            ON u.id=p.user_id

          WHERE p.id=?
        `)
        .bind(id)
        .first();

    return json({
      post
    });
  }

  const postMatch =
    path.match(
      /^\/api\/posts\/(\d+)$/
    );

  if (
    postMatch &&
    method === "GET"
  ) {
    const id =
      Number(postMatch[1]);

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

          JOIN users u
            ON u.id=p.user_id

          WHERE p.id=?
        `)
        .bind(
          Number(user.id),
          String(user.id),
          id
        )
        .first();

    if (!post) {
      throw new HttpError(
        404,
        "Post not found"
      );
    }

    return json({
      post
    });
  }

  if (
    postMatch &&
    method === "DELETE"
  ) {
    const id =
      Number(postMatch[1]);

    const post =
      await env.DB
        .prepare(
          "SELECT user_id FROM posts WHERE id=?"
        )
        .bind(id)
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
        "You can only delete your own post"
      );
    }

    await env.DB.batch([
      env.DB
        .prepare(
          "DELETE FROM comments WHERE post_id=?"
        )
        .bind(id),

      env.DB
        .prepare(
          "DELETE FROM likes WHERE post_id=?"
        )
        .bind(id),

      env.DB
        .prepare(
          "DELETE FROM saved_posts WHERE post_id=?"
        )
        .bind(String(id)),

      env.DB
        .prepare(
          "DELETE FROM notifications WHERE post_id=?"
        )
        .bind(id),

      env.DB
        .prepare(
          "DELETE FROM posts WHERE id=?"
        )
        .bind(id)
    ]);

    return json({
      ok: true
    });
  }

  // =========================
  // LIKE
  // =========================

  const likeMatch =
    path.match(
      /^\/api\/posts\/(\d+)\/like$/
    );

  if (
    likeMatch &&
    method === "POST"
  ) {
    const id =
      Number(likeMatch[1]);

    const post =
      await env.DB
        .prepare(
          "SELECT id,user_id FROM posts WHERE id=?"
        )
        .bind(id)
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
          SELECT id
          FROM likes

          WHERE post_id=?
            AND user_id=?

          LIMIT 1
        `)
        .bind(
          id,
          Number(user.id)
        )
        .first();

    if (existing) {
      await env.DB
        .prepare(
          "DELETE FROM likes WHERE id=?"
        )
        .bind(existing.id)
        .run();
    } else {
      await env.DB
        .prepare(`
          INSERT INTO likes
          (
            post_id,
            user_id
          )
          VALUES (?,?)
        `)
        .bind(
          id,
          Number(user.id)
        )
        .run();

      await notify(
        env,
        post.user_id,
        user.id,
        "like",
        id
      );
    }

    const count =
      await env.DB
        .prepare(`
          SELECT COUNT(*) c
          FROM likes
          WHERE post_id=?
        `)
        .bind(id)
        .first();

    return json({
      liked: !existing,
      likes_count:
        Number(count?.c || 0)
    });
  }

  // =========================
  // SAVE
  // =========================

  const saveMatch =
    path.match(
      /^\/api\/posts\/(\d+)\/save$/
    );

  if (
    saveMatch &&
    method === "POST"
  ) {
    const id =
      Number(saveMatch[1]);

    const existing =
      await env.DB
        .prepare(`
          SELECT post_id
          FROM saved_posts

          WHERE post_id=?
            AND user_id=?
        `)
        .bind(
          String(id),
          String(user.id)
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
          String(id),
          String(user.id)
        )
        .run();
    } else {
      await env.DB
        .prepare(`
          INSERT INTO saved_posts
          (
            post_id,
            user_id,
            created_at
          )
          VALUES (?,?,?)
        `)
        .bind(
          String(id),
          String(user.id),
          new Date().toISOString()
        )
        .run();
    }

    return json({
      saved: !existing
    });
  }

  // =========================
  // COMMENTS
  // =========================

  const commentMatch =
    path.match(
      /^\/api\/posts\/(\d+)\/comments$/
    );

  if (
    commentMatch &&
    method === "GET"
  ) {
    const id =
      Number(commentMatch[1]);

    const r =
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
        `)
        .bind(id)
        .all();

    return json({
      comments:
        r.results || []
    });
  }

  if (
    commentMatch &&
    method === "POST"
  ) {
    const id =
      Number(commentMatch[1]);

    const b =
      await readJSON(req);

    const content =
      clean(
        b.content,
        3000
      );

    if (!content) {
      throw new HttpError(
        400,
        "Comment is empty"
      );
    }

    const post =
      await env.DB
        .prepare(
          "SELECT user_id FROM posts WHERE id=?"
        )
        .bind(id)
        .first();

    if (!post) {
      throw new HttpError(
        404,
        "Post not found"
      );
    }

    const r =
      await env.DB
        .prepare(`
          INSERT INTO comments
          (
            post_id,
            user_id,
            content
          )
          VALUES (?,?,?)
        `)
        .bind(
          id,
          Number(user.id),
          content
        )
        .run();

    const comment =
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

          WHERE c.id=?
        `)
        .bind(
          Number(r.meta.last_row_id)
        )
        .first();

    await notify(
      env,
      post.user_id,
      user.id,
      "comment",
      id
    );

    return json({
      comment
    });
  }

  // =========================
  // STORIES
  // =========================

  if (
    path === "/api/stories/feed" &&
    method === "GET"
  ) {
    return json({
      stories:
        await getStories(
          env,
          user
        )
    });
  }

  if (
    path === "/api/stories" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const content =
      clean(
        b.content ||
        b.text,
        5000
      );

    const media =
      clean(
        b.media_url,
        2000
      );

    const mediaType =
      clean(
        b.media_type,
        100
      );

    if (
      !content &&
      !media
    ) {
      throw new HttpError(
        400,
        "Story needs text or media"
      );
    }

    const r =
      await env.DB
        .prepare(`
          INSERT INTO stories
          (
            user_id,
            content,
            media_url,
            media_type
          )
          VALUES (?,?,?,?)
        `)
        .bind(
          Number(user.id),
          content,
          media,
          mediaType
        )
        .run();

    const story =
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

          WHERE s.id=?
        `)
        .bind(
          Number(r.meta.last_row_id)
        )
        .first();

    return json({
      story
    });
  }

  // =========================
  // REELS
  // =========================

  if (
    path === "/api/reels/feed" &&
    method === "GET"
  ) {
    return json({
      reels:
        await getReels(env)
    });
  }

  if (
    path === "/api/reels" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const caption =
      clean(
        b.caption,
        5000
      );

    const media =
      clean(
        b.media_url ||
        b.video_url,
        2000
      );

    if (!media) {
      throw new HttpError(
        400,
        "Reel video is required"
      );
    }

    const r =
      await env.DB
        .prepare(`
          INSERT INTO reels
          (
            user_id,
            caption,
            media_url
          )
          VALUES (?,?,?)
        `)
        .bind(
          Number(user.id),
          caption,
          media
        )
        .run();

    const reel =
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

          WHERE r.id=?
        `)
        .bind(
          Number(r.meta.last_row_id)
        )
        .first();

    return json({
      reel
    });
  }

  // =========================
  // CHATS
  // =========================

  if (
    path === "/api/chats" &&
    method === "GET"
  ) {
    return json({
      chats:
        await chatsForUser(
          env,
          user
        )
    });
  }

  if (
    path === "/api/chats" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const target =
      b.user_id ??
      (Array.isArray(
        b.user_ids
      )
        ? b.user_ids[0]
        : null);

    return json({
      chat:
        await createChat(
          env,
          user,
          target
        )
    });
  }

  if (
    path === "/api/groups" &&
    method === "POST"
  ) {
    return json({
      chat:
        await createGroup(
          env,
          user,
          await readJSON(req)
        )
    });
  }

  const chatMatch =
    path.match(
      /^\/api\/chats\/(\d+)$/
    );

  if (
    chatMatch &&
    method === "GET"
  ) {
    return json({
      chat:
        await chatInfo(
          env,
          user,
          Number(
            chatMatch[1]
          )
        )
    });
  }

  // =========================
  // CHAT MESSAGES
  // =========================

  const messageMatch =
    path.match(
      /^\/api\/chats\/(\d+)\/messages$/
    );

  if (
    messageMatch &&
    method === "GET"
  ) {
    return json({
      messages:
        await getMessages(
          env,
          user,
          Number(
            messageMatch[1]
          )
        )
    });
  }

  if (
    messageMatch &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    return json({
      message:
        await sendMessage(
          env,
          user,
          Number(
            messageMatch[1]
          ),
          b.content
        )
    });
  }

  // =========================
  // NOTIFICATIONS
  // =========================

  if (
    path === "/api/notifications" &&
    method === "GET"
  ) {
    const r =
      await env.DB
        .prepare(`
          SELECT
            n.*,

            u.username
              actor_username,

            u.display_name
              actor_display_name,

            u.avatar_url
              actor_avatar_url

          FROM notifications n

          LEFT JOIN users u
            ON u.id=n.actor_id

          WHERE n.user_id=?

          ORDER BY n.id DESC

          LIMIT 100
        `)
        .bind(
          Number(user.id)
        )
        .all();

    const notifications =
      (r.results || [])
        .map(n => ({
          ...n,

          read:
            Boolean(n.is_read),

          actor: {
            id: n.actor_id,

            username:
              n.actor_username,

            display_name:
              n.actor_display_name,

            avatar_url:
              n.actor_avatar_url
          }
        }));

    return json({
      notifications,

      unread_count:
        notifications.filter(
          n => !n.read
        ).length
    });
  }

  if (
    path === "/api/notifications/read" &&
    method === "POST"
  ) {
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
      ok: true
    });
  }

  // =========================
  // SETTINGS
  // =========================

  if (
    path === "/api/settings" &&
    method === "GET"
  ) {
    return json({
      settings:
        await settingsFor(
          env,
          user.id
        )
    });
  }

  if (
    path === "/api/settings" &&
    (
      method === "POST" ||
      method === "PATCH"
    )
  ) {
    const b =
      await readJSON(req);

    const old =
      await settingsFor(
        env,
        user.id
      );

    const theme =
      [
        "system",
        "dark",
        "light"
      ].includes(b.theme)
        ? b.theme
        : old.theme;

    const visibility =
      [
        "public",
        "private"
      ].includes(
        b.profile_visibility
      )
        ? b.profile_visibility
        : old.profile_visibility;

    const messagePrivacy =
      [
        "everyone",
        "followers",
        "nobody"
      ].includes(
        b.message_privacy
      )
        ? b.message_privacy
        : old.message_privacy;

    const notifications =
      (
        b.notification_settings &&
        typeof b.notification_settings ===
          "object"
      )
        ? {
            ...old.notification_settings,
            ...b.notification_settings
          }
        : old.notification_settings;

    await env.DB
      .prepare(`
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

          profile_visibility=
            excluded.profile_visibility,

          message_privacy=
            excluded.message_privacy,

          notification_settings=
            excluded.notification_settings
      `)
      .bind(
        String(user.id),
        theme,
        visibility,
        messagePrivacy,
        JSON.stringify(
          notifications
        )
      )
      .run();

    return json({
      settings:
        await settingsFor(
          env,
          user.id
        )
    });
  }

  // =========================
  // UPLOAD
  // =========================

  if (
    path === "/api/upload" &&
    method === "POST"
  ) {
    return json(
      await uploadFile(
        env,
        user,
        req
      )
    );
  }

  throw new HttpError(
    404,
    "Route not found"
  );
}

export default {
  async fetch(
    req,
    env
  ) {
    try {
      return await route(
        req,
        env
      );
    } catch (e) {
      if (
        e instanceof HttpError
      ) {
        return error(
          e.status,
          e.message
        );
      }

      console.error(
        "ZILNET WORKER ERROR:",
        e
      );

      return error(
        500,
        "Internal server error"
      );
    }
  }
};
