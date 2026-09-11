const SESSION_DAYS = 30;
const RESET_MINUTES = 15;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extra
    }
  });
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

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function token() {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return b64(a);
}

async function sha256(text) {
  const d = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );

  return [...new Uint8Array(d)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function hashPassword(
  password,
  salt = token(),
  iterations = 120000
) {
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
      salt: new TextEncoder().encode(salt),
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

function cookie(req, name) {
  const raw = req.headers.get("Cookie") || "";

  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");

    if (k === name) {
      return v.join("=");
    }
  }

  return "";
}

function setSession(tokenValue) {
  return [
    `zilnet_session=${tokenValue}`,
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

function publicUser(u) {
  if (!u) return null;

  return {
    id: String(u.id),
    username: u.username || "",
    display_name: u.display_name || "",
    bio: u.bio || "",
    skills: u.skills || "[]",
    avatar_url: u.avatar_url || "",
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

function parseJSON(v, fallback = {}) {
  try {
    return JSON.parse(v || "{}");
  } catch {
    return fallback;
  }
}

async function getUserById(env, uid) {
  return env.DB
    .prepare(
      "SELECT * FROM users WHERE id=? LIMIT 1"
    )
    .bind(String(uid))
    .first();
}

async function requireUser(req, env) {
  const raw = cookie(
    req,
    "zilnet_session"
  );

  if (!raw) {
    throw new HttpError(
      401,
      "Session expired"
    );
  }

  const hash = await sha256(raw);

  const row = await env.DB
    .prepare(`
      SELECT u.*
      FROM sessions s
      JOIN users u
        ON u.id=s.user_id
      WHERE s.token_hash=?
        AND s.expires_at>?
      LIMIT 1
    `)
    .bind(
      hash,
      Date.now()
    )
    .first();

  if (!row) {
    throw new HttpError(
      401,
      "Session expired"
    );
  }

  return row;
}

async function settingsFor(env, uid) {
  const userId = String(uid);

  let s = await env.DB
    .prepare(`
      SELECT *
      FROM user_settings
      WHERE user_id=?
    `)
    .bind(userId)
    .first();

  if (!s) {
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
      `)
      .bind(
        userId,
        "system",
        "public",
        "everyone",
        "{}"
      )
      .run();

    s = await env.DB
      .prepare(`
        SELECT *
        FROM user_settings
        WHERE user_id=?
      `)
      .bind(userId)
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
  receiverId,
  actorId,
  type,
  postId = null
) {
  if (
    String(receiverId) ===
    String(actorId)
  ) {
    return;
  }

  const s = await settingsFor(
    env,
    receiverId
  );

  const key = {
    like: "likes",
    comment: "comments",
    follow: "follows",
    message: "messages"
  }[type];

  if (
    key &&
    s.notification_settings?.[key] === false
  ) {
    return;
  }

  await env.DB
    .prepare(`
      INSERT INTO notifications
      (
        id,
        user_id,
        actor_id,
        type,
        post_id,
        is_read,
        created_at
      )
      VALUES (?,?,?,?,?,?,?)
    `)
    .bind(
      id(),
      String(receiverId),
      String(actorId),
      type,
      postId
        ? String(postId)
        : null,
      0,
      now()
    )
    .run();
}

async function findUser(
  env,
  identifier
) {
  const x = clean(
    identifier,
    200
  ).toLowerCase();

  return env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE lower(username)=?
         OR lower(email)=?
      LIMIT 1
    `)
    .bind(x, x)
    .first();
}

async function userByUsername(
  env,
  username
) {
  return env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE lower(username)=lower(?)
      LIMIT 1
    `)
    .bind(
      clean(username, 30)
    )
    .first();
}

async function counts(
  env,
  uid
) {
  const [
    followers,
    following
  ] = await Promise.all([
    env.DB
      .prepare(`
        SELECT COUNT(*) c
        FROM follows
        WHERE following_id=?
      `)
      .bind(String(uid))
      .first(),

    env.DB
      .prepare(`
        SELECT COUNT(*) c
        FROM follows
        WHERE follower_id=?
      `)
      .bind(String(uid))
      .first()
  ]);

  return {
    followers:
      Number(followers?.c || 0),
    following:
      Number(following?.c || 0)
  };
}

async function profile(
  env,
  viewer,
  username
) {
  const u =
    await userByUsername(
      env,
      username
    );

  if (!u) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const settings =
    await settingsFor(
      env,
      u.id
    );

  const isOwn =
    viewer &&
    String(viewer.id) ===
      String(u.id);

  const isFollowing =
    viewer
      ? !!(
          await env.DB
            .prepare(`
              SELECT 1
              FROM follows
              WHERE follower_id=?
                AND following_id=?
              LIMIT 1
            `)
            .bind(
              String(viewer.id),
              String(u.id)
            )
            .first()
        )
      : false;

  const c =
    await counts(
      env,
      u.id
    );

  const resultUser = {
    ...publicUser(u),
    followers_count:
      c.followers,
    following_count:
      c.following,
    following:
      isFollowing
  };

  if (
    settings.profile_visibility ===
      "private" &&
    !isOwn &&
    !isFollowing
  ) {
    return {
      user: resultUser,
      posts: [],
      private: true
    };
  }

  const viewerId =
    viewer
      ? String(viewer.id)
      : "";

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
            FROM likes l2
            WHERE l2.post_id=p.id
              AND l2.user_id=?
          ) liked,

          EXISTS(
            SELECT 1
            FROM saved_posts s
            WHERE s.post_id=p.id
              AND s.user_id=?
          ) saved

        FROM posts p
        JOIN users u
          ON u.id=p.user_id

        WHERE p.user_id=?
          AND p.visibility='public'

        ORDER BY p.created_at DESC
      `)
      .bind(
        viewerId,
        viewerId,
        String(u.id)
      )
      .all();

  return {
    user: resultUser,
    posts:
      posts.results || [],
    private: false
  };
}

async function feed(
  env,
  user
) {
  const uid =
    String(user.id);

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
            FROM likes l2
            WHERE l2.post_id=p.id
              AND l2.user_id=?
          ) liked,

          EXISTS(
            SELECT 1
            FROM saved_posts s
            WHERE s.post_id=p.id
              AND s.user_id=?
          ) saved

        FROM posts p
        JOIN users u
          ON u.id=p.user_id

        WHERE p.visibility='public'

        ORDER BY p.created_at DESC
        LIMIT 100
      `)
      .bind(uid, uid)
      .all();

  return {
    posts:
      posts.results || [],

    stories:
      await storyFeed(
        env,
        user
      )
  };
}

async function storyFeed(
  env,
  user
) {
  const uid =
    String(user.id);

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

        WHERE s.expires_at>?
          AND (
            s.user_id=?
            OR s.user_id IN (
              SELECT following_id
              FROM follows
              WHERE follower_id=?
            )
          )

        ORDER BY s.created_at DESC
      `)
      .bind(
        Date.now(),
        uid,
        uid
      )
      .all();

  return r.results || [];
}

async function postById(
  env,
  viewerId,
  postId
) {
  const uid =
    String(viewerId || "");

  const p =
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
            FROM saved_posts s
            WHERE s.post_id=p.id
              AND s.user_id=?
          ) saved

        FROM posts p
        JOIN users u
          ON u.id=p.user_id

        WHERE p.id=?
        LIMIT 1
      `)
      .bind(
        uid,
        uid,
        String(postId)
      )
      .first();

  if (!p) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  return p;
}

async function chatInfo(
  env,
  user,
  chatId
) {
  const c =
    await env.DB
      .prepare(`
        SELECT *
        FROM chats
        WHERE id=?
      `)
      .bind(String(chatId))
      .first();

  if (!c) {
    throw new HttpError(
      404,
      "Chat not found"
    );
  }

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
        String(chatId),
        String(user.id)
      )
      .first();

  if (!member) {
    throw new HttpError(
      403,
      "Not a member of this chat"
    );
  }

  if (c.type === "group") {
    return {
      ...c,
      type: "group",
      is_group: true,
      username: "",
      avatar_url: ""
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
        String(chatId),
        String(user.id)
      )
      .first();

  return {
    ...c,
    type: "direct",
    is_group: false,

    name:
      other?.display_name ||
      other?.username ||
      "Chat",

    username:
      other?.username || "",

    avatar_url:
      other?.avatar_url || "",

    user:
      publicUser(other)
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
          c.*,

          (
            SELECT m.content
            FROM messages m
            WHERE m.chat_id=c.id
            ORDER BY m.created_at DESC
            LIMIT 1
          ) last_message,

          (
            SELECT m.created_at
            FROM messages m
            WHERE m.chat_id=c.id
            ORDER BY m.created_at DESC
            LIMIT 1
          ) last_message_at

        FROM chats c

        JOIN chat_members cm
          ON cm.chat_id=c.id

        WHERE cm.user_id=?

        ORDER BY
          COALESCE(
            last_message_at,
            c.created_at
          ) DESC
      `)
      .bind(
        String(user.id)
      )
      .all();

  const out = [];

  for (
    const c of
      r.results || []
  ) {
    out.push({
      ...(await chatInfo(
        env,
        user,
        c.id
      )),

      last_message:
        c.last_message || "",

      last_message_at:
        c.last_message_at || ""
    });
  }

  return out;
}

async function createDirectChat(
  env,
  user,
  targetId
) {
  targetId =
    String(targetId || "");

  if (
    !targetId ||
    targetId === String(user.id)
  ) {
    throw new HttpError(
      400,
      "Invalid user"
    );
  }

  const target =
    await getUserById(
      env,
      targetId
    );

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
    const follows =
      await env.DB
        .prepare(`
          SELECT 1
          FROM follows
          WHERE follower_id=?
            AND following_id=?
          LIMIT 1
        `)
        .bind(
          String(user.id),
          targetId
        )
        .first();

    if (!follows) {
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

        WHERE c.type='direct'
        LIMIT 1
      `)
      .bind(
        String(user.id),
        targetId
      )
      .first();

  if (existing) {
    return chatInfo(
      env,
      user,
      existing.id
    );
  }

  const chatId = id();
  const t = now();

  await env.DB.batch([
    env.DB
      .prepare(`
        INSERT INTO chats
        (
          id,
          type,
          name,
          created_at
        )
        VALUES (?,?,?,?)
      `)
      .bind(
        chatId,
        "direct",
        "",
        t
      ),

    env.DB
      .prepare(`
        INSERT INTO chat_members
        (
          chat_id,
          user_id,
          joined_at
        )
        VALUES (?,?,?)
      `)
      .bind(
        chatId,
        String(user.id),
        t
      ),

    env.DB
      .prepare(`
        INSERT INTO chat_members
        (
          chat_id,
          user_id,
          joined_at
        )
        VALUES (?,?,?)
      `)
      .bind(
        chatId,
        targetId,
        t
      )
  ]);

  return chatInfo(
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
    clean(
      body.name,
      80
    ) || "New group";

  const ids = [
    ...new Set(
      (
        Array.isArray(
          body.user_ids
        )
          ? body.user_ids
          : []
      )
        .map(x => String(x))
        .filter(
          x =>
            x &&
            x !== String(user.id)
        )
    )
  ];

  if (ids.length > 49) {
    throw new HttpError(
      400,
      "Maximum 50 group members"
    );
  }

  for (
    const uid of ids
  ) {
    if (
      !(await getUserById(
        env,
        uid
      ))
    ) {
      throw new HttpError(
        400,
        "One or more users do not exist"
      );
    }
  }

  const chatId = id();
  const t = now();

  const statements = [
    env.DB
      .prepare(`
        INSERT INTO chats
        (
          id,
          type,
          name,
          created_at
        )
        VALUES (?,?,?,?)
      `)
      .bind(
        chatId,
        "group",
        name,
        t
      ),

    env.DB
      .prepare(`
        INSERT INTO chat_members
        (
          chat_id,
          user_id,
          joined_at
        )
        VALUES (?,?,?)
      `)
      .bind(
        chatId,
        String(user.id),
        t
      )
  ];

  for (
    const uid of ids
  ) {
    statements.push(
      env.DB
        .prepare(`
          INSERT INTO chat_members
          (
            chat_id,
            user_id,
            joined_at
          )
          VALUES (?,?,?)
        `)
        .bind(
          chatId,
          uid,
          t
        )
    );
  }

  await env.DB.batch(
    statements
  );

  return chatInfo(
    env,
    user,
    chatId
  );
}

async function getMessages(
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
        String(chatId),
        String(user.id)
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

        ORDER BY m.created_at ASC
        LIMIT 500
      `)
      .bind(
        String(chatId)
      )
      .all();

  return r.results || [];
}

async function sendMessage(
  env,
  user,
  chatId,
  content,
  mediaUrl = ""
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
        String(chatId),
        String(user.id)
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

  const media =
    clean(mediaUrl, 2000);

  if (!text && !media) {
    throw new HttpError(
      400,
      "Message is empty"
    );
  }

  const messageId = id();
  const t = now();

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
      String(chatId),
      String(user.id),
      text,
      media,
      t
    )
    .run();

  const members =
    await env.DB
      .prepare(`
        SELECT user_id
        FROM chat_members
        WHERE chat_id=?
          AND user_id<>?
      `)
      .bind(
        String(chatId),
        String(user.id)
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

  return env.DB
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
    .bind(messageId)
    .first();
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
    `media/${user.id}/${Date.now()}-${token().slice(0,10)}${ext}`;

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

async function sendResetEmail(
  env,
  email,
  code
) {
  if (
    !env.RESEND_API_KEY ||
    !env.RESEND_FROM
  ) {
    throw new HttpError(
      503,
      "Password reset email is not configured"
    );
  }

  const response =
    await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",

        headers: {
          "Authorization":
            `Bearer ${env.RESEND_API_KEY}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          from:
            env.RESEND_FROM,

          to: [email],

          subject:
            "Your ZILNET password reset code",

          text:
            `Your ZILNET password reset code is ${code}. It expires in ${RESET_MINUTES} minutes.`
        })
      }
    );

  if (!response.ok) {
    throw new HttpError(
      502,
      "Unable to send reset email"
    );
  }
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

  // SIGNUP

  if (
    path === "/api/signup" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const username =
      clean(
        b.username,
        30
      );

    const email =
      clean(
        b.email,
        200
      ).toLowerCase();

    const password =
      String(
        b.password || ""
      );

    const displayName =
      clean(
        b.display_name ||
        username,
        80
      );

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

    if (
      password.length < 8
    ) {
      throw new HttpError(
        400,
        "Password must be at least 8 characters"
      );
    }

    if (
      await env.DB
        .prepare(`
          SELECT 1
          FROM users
          WHERE lower(username)=lower(?)
        `)
        .bind(username)
        .first()
    ) {
      throw new HttpError(
        409,
        "Username already exists"
      );
    }

    if (
      await env.DB
        .prepare(`
          SELECT 1
          FROM users
          WHERE lower(email)=lower(?)
        `)
        .bind(email)
        .first()
    ) {
      throw new HttpError(
        409,
        "Email already exists"
      );
    }

    const userId = id();
    const t = now();

    const passwordHash =
      await hashPassword(
        password
      );

    await env.DB.batch([
      env.DB
        .prepare(`
          INSERT INTO users
          (
            id,
            username,
            display_name,
            email,
            password_hash,
            bio,
            skills,
            avatar_url,
            created_at
          )
          VALUES (?,?,?,?,?,?,?,?,?)
        `)
        .bind(
          userId,
          username,
          displayName,
          email,
          passwordHash,
          "",
          "[]",
          "",
          t
        ),

      env.DB
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
        `)
        .bind(
          userId,
          "system",
          "public",
          "everyone",
          "{}"
        )
    ]);

    const session =
      token();

    await env.DB
      .prepare(`
        INSERT INTO sessions
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
        id(),
        userId,
        await sha256(session),
        Date.now() +
          SESSION_DAYS *
          86400000,
        t
      )
      .run();

    const u =
      await getUserById(
        env,
        userId
      );

    return json(
      {
        user:
          ownUser(u)
      },
      201,
      {
        "Set-Cookie":
          setSession(session)
      }
    );
  }

  // LOGIN

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
      );

    const password =
      String(
        b.password || ""
      );

    const u =
      await findUser(
        env,
        identifier
      );

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

    const session =
      token();

    await env.DB
      .prepare(`
        INSERT INTO sessions
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
        id(),
        String(u.id),
        await sha256(session),
        Date.now() +
          SESSION_DAYS *
          86400000,
        now()
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
          setSession(session)
      }
    );
  }

  // LOGOUT

  if (
    path === "/api/logout" &&
    method === "POST"
  ) {
    const raw =
      cookie(
        req,
        "zilnet_session"
      );

    if (raw) {
      await env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE token_hash=?
        `)
        .bind(
          await sha256(raw)
        )
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

  // ME

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

  // FORGOT PASSWORD

  if (
    (
      path ===
        "/api/forgot-password" ||
      path ===
        "/api/password-reset"
    ) &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const email =
      clean(
        b.email,
        200
      ).toLowerCase();

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
      id();

    if (u) {
      const code =
        String(
          Math.floor(
            100000 +
            Math.random() *
              900000
          )
        );

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
          await sha256(code),
          Date.now() +
            RESET_MINUTES *
            60000,
          now()
        )
        .run();

      await sendResetEmail(
        env,
        email,
        code
      );
    }

    return json({
      ok: true,
      reset_id:
        resetId
    });
  }

  // RESET PASSWORD

  if (
    path ===
      "/api/reset-password" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const resetId =
      clean(
        b.reset_id,
        100
      );

    const code =
      clean(
        b.code,
        20
      );

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
          await sha256(code),
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

    const session =
      token();

    const t = now();

    await env.DB.batch([
      env.DB
        .prepare(`
          UPDATE users
          SET password_hash=?
          WHERE id=?
        `)
        .bind(
          passwordHash,
          String(reset.user_id)
        ),

      env.DB
        .prepare(`
          DELETE FROM password_resets
          WHERE id=?
        `)
        .bind(resetId),

      env.DB
        .prepare(`
          DELETE FROM sessions
          WHERE user_id=?
        `)
        .bind(
          String(reset.user_id)
        ),

      env.DB
        .prepare(`
          INSERT INTO sessions
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
          id(),
          String(reset.user_id),
          await sha256(session),
          Date.now() +
            SESSION_DAYS *
            86400000,
          t
        )
    ]);

    return json(
      {
        ok: true,

        user:
          ownUser(
            await getUserById(
              env,
              reset.user_id
            )
          )
      },
      200,
      {
        "Set-Cookie":
          setSession(session)
      }
    );
  }

  // PUBLIC MEDIA

  if (
    path.startsWith(
      "/media/"
    ) &&
    method === "GET"
  ) {
    if (!env.MEDIA) {
      return new Response(
        "Media storage is not configured",
        { status: 503 }
      );
    }

    const key =
      decodeURIComponent(
        path.slice(7)
      );

    const object =
      await env.MEDIA.get(
        key
      );

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

  const user =
    await requireUser(
      req,
      env
    );

  // PROFILE

  if (
    path ===
      "/api/profile" &&
    method === "GET"
  ) {
    return json(
      await profile(
        env,
        user,
        user.username
      )
    );
  }

  const publicProfile =
    path.match(
      /^\/api\/(?:profile|users)\/([^/]+)$/
    );

  if (
    publicProfile &&
    method === "GET"
  ) {
    return json(
      await profile(
        env,
        user,
        decodeURIComponent(
          publicProfile[1]
        )
      )
    );
  }

  // PROFILE UPDATE

  if (
    path ===
      "/api/profile/update" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const skills =
      typeof b.skills ===
      "string"
        ? b.skills
        : JSON.stringify(
            b.skills || []
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
        clean(
          b.display_name,
          80
        ),

        clean(
          b.bio,
          500
        ),

        skills,

        clean(
          b.avatar_url,
          2000
        ),

        String(user.id)
      )
      .run();

    return json({
      user:
        ownUser(
          await getUserById(
            env,
            user.id
          )
        )
    });
  }

  // CHANGE PASSWORD

  if (
    path ===
      "/api/profile/password" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const current =
      String(
        b.current_password ||
        ""
      );

    const next =
      String(
        b.new_password ||
        ""
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

    await env.DB
      .prepare(`
        UPDATE users
        SET password_hash=?
        WHERE id=?
      `)
      .bind(
        await hashPassword(
          next
        ),
        String(user.id)
      )
      .run();

    return json({
      ok: true
    });
  }

  // FOLLOW

  const follow =
    path.match(
      /^\/api\/users\/([^/]+)\/follow$/
    );

  if (
    follow &&
    method === "POST"
  ) {
    const target =
      decodeURIComponent(
        follow[1]
      );

    if (
      target ===
      String(user.id)
    ) {
      throw new HttpError(
        400,
        "You cannot follow yourself"
      );
    }

    if (
      !(await getUserById(
        env,
        target
      ))
    ) {
      throw new HttpError(
        404,
        "User not found"
      );
    }

    const existing =
      await env.DB
        .prepare(`
          SELECT 1
          FROM follows
          WHERE follower_id=?
            AND following_id=?
          LIMIT 1
        `)
        .bind(
          String(user.id),
          target
        )
        .first();

    if (existing) {
      await env.DB
        .prepare(`
          DELETE FROM follows
          WHERE follower_id=?
            AND following_id=?
        `)
        .bind(
          String(user.id),
          target
        )
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
          following_id,
          created_at
        )
        VALUES (?,?,?)
      `)
      .bind(
        String(user.id),
        target,
        now()
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

  // FEED

  if (
    path === "/api/feed" &&
    method === "GET"
  ) {
    return json(
      await feed(
        env,
        user
      )
    );
  }

  // SEARCH

  if (
    (
      path === "/api/search" ||
      path === "/api/suggestions"
    ) &&
    method === "GET"
  ) {
    const q =
      clean(
        url.searchParams.get(
          "q"
        ) || "",
        80
      );

    const like =
      `%${q}%`;

    const r =
      await env.DB
        .prepare(`
          SELECT
            id,
            username,
            display_name,
            bio,
            avatar_url

          FROM users

          WHERE username LIKE ?
             OR display_name LIKE ?

          ORDER BY username
          LIMIT 50
        `)
        .bind(
          like,
          like
        )
        .all();

    return json({
      users:
        r.results || [],

      suggestions:
        r.results || []
    });
  }

  // UPLOAD

  if (
    path ===
      "/api/upload" &&
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
    // CREATE POST

  if (
    path ===
      "/api/posts" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const content =
      clean(
        b.content,
        5000
      );

    const mediaUrl =
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
      !mediaUrl
    ) {
      throw new HttpError(
        400,
        "Post needs text or media"
      );
    }

    const postId =
      id();

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
        String(user.id),
        content,
        mediaUrl,
        mediaType,
        "public",
        now()
      )
      .run();

    return json(
      {
        post:
          await postById(
            env,
            user.id,
            postId
          )
      },
      201
    );
  }

  // GET POST

  const postMatch =
    path.match(
      /^\/api\/posts\/([^/]+)$/
    );

  if (
    postMatch &&
    method === "GET"
  ) {
    return json({
      post:
        await postById(
          env,
          user.id,
          decodeURIComponent(
            postMatch[1]
          )
        )
    });
  }

  // DELETE POST

  if (
    postMatch &&
    method === "DELETE"
  ) {
    const postId =
      decodeURIComponent(
        postMatch[1]
      );

    const p =
      await env.DB
        .prepare(`
          SELECT user_id
          FROM posts
          WHERE id=?
        `)
        .bind(postId)
        .first();

    if (!p) {
      throw new HttpError(
        404,
        "Post not found"
      );
    }

    if (
      String(p.user_id) !==
      String(user.id)
    ) {
      throw new HttpError(
        403,
        "You can only delete your own post"
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

  // LIKE

  const like =
    path.match(
      /^\/api\/posts\/([^/]+)\/like$/
    );

  if (
    like &&
    method === "POST"
  ) {
    const postId =
      decodeURIComponent(
        like[1]
      );

    const p =
      await env.DB
        .prepare(`
          SELECT user_id
          FROM posts
          WHERE id=?
        `)
        .bind(postId)
        .first();

    if (!p) {
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
        `)
        .bind(
          postId,
          String(user.id)
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
          String(user.id)
        )
        .run();
    } else {
      await env.DB
        .prepare(`
          INSERT INTO likes
          (
            post_id,
            user_id,
            created_at
          )
          VALUES (?,?,?)
        `)
        .bind(
          postId,
          String(user.id),
          now()
        )
        .run();

      await notify(
        env,
        p.user_id,
        user.id,
        "like",
        postId
      );
    }

    const count =
      await env.DB
        .prepare(`
          SELECT COUNT(*) c
          FROM likes
          WHERE post_id=?
        `)
        .bind(postId)
        .first();

    return json({
      liked:
        !existing,

      likes_count:
        Number(
          count?.c || 0
        )
    });
  }

  // SAVE POST

  const save =
    path.match(
      /^\/api\/posts\/([^/]+)\/save$/
    );

  if (
    save &&
    method === "POST"
  ) {
    const postId =
      decodeURIComponent(
        save[1]
      );

    if (
      !(await env.DB
        .prepare(`
          SELECT 1
          FROM posts
          WHERE id=?
        `)
        .bind(postId)
        .first())
    ) {
      throw new HttpError(
        404,
        "Post not found"
      );
    }

    const existing =
      await env.DB
        .prepare(`
          SELECT 1
          FROM saved_posts
          WHERE post_id=?
            AND user_id=?
        `)
        .bind(
          postId,
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
          postId,
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
          postId,
          String(user.id),
          now()
        )
        .run();
    }

    return json({
      saved:
        !existing
    });
  }

  // COMMENTS

  const comments =
    path.match(
      /^\/api\/posts\/([^/]+)\/comments$/
    );

  if (
    comments &&
    method === "GET"
  ) {
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

          ORDER BY c.created_at ASC
        `)
        .bind(
          decodeURIComponent(
            comments[1]
          )
        )
        .all();

    return json({
      comments:
        r.results || []
    });
  }

  if (
    comments &&
    method === "POST"
  ) {
    const postId =
      decodeURIComponent(
        comments[1]
      );

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

    const p =
      await env.DB
        .prepare(`
          SELECT user_id
          FROM posts
          WHERE id=?
        `)
        .bind(postId)
        .first();

    if (!p) {
      throw new HttpError(
        404,
        "Post not found"
      );
    }

    const commentId =
      id();

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
        String(user.id),
        content,
        now()
      )
      .run();

    await notify(
      env,
      p.user_id,
      user.id,
      "comment",
      postId
    );

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
        .bind(commentId)
        .first();

    return json(
      { comment },
      201
    );
  }

  // STORIES

  if (
    path ===
      "/api/stories/feed" &&
    method === "GET"
  ) {
    return json({
      stories:
        await storyFeed(
          env,
          user
        )
    });
  }

  if (
    path ===
      "/api/stories" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const text =
      clean(
        b.text ||
        b.content,
        5000
      );

    const media =
      clean(
        b.media_url,
        2000
      );

    if (
      !text &&
      !media
    ) {
      throw new HttpError(
        400,
        "Story needs text or media"
      );
    }

    const storyId =
      id();

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
        String(user.id),
        text,
        media,
        now(),
        Date.now() +
          86400000
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
        .bind(storyId)
        .first();

    return json(
      { story },
      201
    );
  }

  // REELS

  if (
    path ===
      "/api/reels/feed" &&
    method === "GET"
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

          ORDER BY r.created_at DESC
          LIMIT 100
        `)
        .all();

    return json({
      reels:
        r.results || []
    });
  }

  if (
    path ===
      "/api/reels" &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    const video =
      clean(
        b.video_url ||
        b.media_url,
        2000
      );

    const caption =
      clean(
        b.caption,
        5000
      );

    if (!video) {
      throw new HttpError(
        400,
        "Reel video is required"
      );
    }

    const reelId =
      id();

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
        String(user.id),
        video,
        caption,
        now()
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
        .bind(reelId)
        .first();

    return json(
      { reel },
      201
    );
  }

  // CHATS

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

    return json(
      {
        chat:
          await createDirectChat(
            env,
            user,
            b.user_id
          )
      },
      201
    );
  }

  if (
    path === "/api/groups" &&
    method === "POST"
  ) {
    return json(
      {
        chat:
          await createGroup(
            env,
            user,
            await readJSON(req)
          )
      },
      201
    );
  }

  const chat =
    path.match(
      /^\/api\/chats\/([^/]+)$/
    );

  if (
  chat &&
  method === "GET"
) {
  return json({
    chat: await chatInfo(
      env,
      user,
      decodeURIComponent(chat[1])
    )
  });
}

  // CHAT MESSAGES

  const messages =
    path.match(
      /^\/api\/chats\/([^/]+)\/messages$/
    );

  if (
    messages &&
    method === "GET"
  ) {
    return json({
      messages:
        await getMessages(
          env,
          user,
          decodeURIComponent(
            messages[1]
          )
        )
    });
  }

  if (
    messages &&
    method === "POST"
  ) {
    const b =
      await readJSON(req);

    return json(
      {
        message:
          await sendMessage(
            env,
            user,
            decodeURIComponent(
              messages[1]
            ),
            b.content,
            b.media_url
          )
      },
      201
    );
  }

  // NOTIFICATIONS

  if (
    path ===
      "/api/notifications" &&
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

          ORDER BY n.created_at DESC
          LIMIT 100
        `)
        .bind(
          String(user.id)
        )
        .all();

    const notifications =
      (
        r.results || []
      ).map(n => ({
        ...n,

        read:
          Boolean(
            n.is_read
          ),

        actor: {
          id:
            n.actor_id,

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
          x => !x.read
        ).length
    });
  }

  if (
    path ===
      "/api/notifications/read" &&
    method === "POST"
  ) {
    await env.DB
      .prepare(`
        UPDATE notifications
        SET is_read=1
        WHERE user_id=?
      `)
      .bind(
        String(user.id)
      )
      .run();

    return json({
      ok: true
    });
  }

  // SETTINGS

  if (
    path ===
      "/api/settings" &&
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
    path ===
      "/api/settings" &&
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
      ].includes(
        b.theme
      )
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
      b.notification_settings &&
      typeof b.notification_settings ===
        "object"
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
          profile_visibility=excluded.profile_visibility,
          message_privacy=excluded.message_privacy,
          notification_settings=excluded.notification_settings
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

  throw new HttpError(
    404,
    "Not found"
  );
}

export default {
  async fetch(
    req,
    env,
    ctx
  ) {
    try {
      if (
        req.method ===
        "OPTIONS"
      ) {
        return new Response(
          null,
          {
            status: 204,

            headers: {
              "Access-Control-Allow-Origin":
                new URL(
                  req.url
                ).origin,

              "Access-Control-Allow-Credentials":
                "true",

              "Access-Control-Allow-Headers":
                "Content-Type",

              "Access-Control-Allow-Methods":
                "GET,POST,PATCH,DELETE,OPTIONS"
            }
          }
        );
      }

      const response =
        await route(
          req,
          env
        );

      response.headers.set(
        "Access-Control-Allow-Credentials",
        "true"
      );

      return response;
    } catch (e) {
      console.error(e);

      if (
        e instanceof HttpError
      ) {
        return json(
          {
            error:
              e.message
          },
          e.status
        );
      }

      return json(
        {
          error:
            "Internal server error"
        },
        500
      );
    }
  }
};
  
