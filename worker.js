export default {
  async fetch(request, env) {
    try {
      await ensureSchema(env);

      const url = new URL(request.url);

      if (url.pathname.startsWith("/api/")) {
        return await handleAPI(request, env, url);
      }

      if (url.pathname.startsWith("/media/")) {
        return await handleMedia(request, env, url);
      }

      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("ZILNET ERROR:", error);

      return json({
        error: "Server error.",
        detail: error.message
      }, 500);
    }
  }
};


/* =========================================================
   RESPONSE HELPERS
   ========================================================= */

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store"
      }
    }
  );
}

function text(data, status = 200) {
  return new Response(
    String(data),
    {
      status,
      headers: {
        "Content-Type": "text/plain; charset=utf-8"
      }
    }
  );
}


/* =========================================================
   DATABASE SCHEMA
   ========================================================= */

let schemaPromise = null;

function ensureSchema(env) {
  if (schemaPromise) return schemaPromise;

  schemaPromise = (async () => {

    const statements = [

      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT UNIQUE,
        display_name TEXT,
        password_hash TEXT,
        password_salt TEXT,
        bio TEXT DEFAULT '',
        avatar_url TEXT DEFAULT '',
        skills TEXT DEFAULT '',
        is_private INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT,
        media_url TEXT DEFAULT '',
        media_type TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )`,

      `CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(post_id, user_id)
      )`,

      `CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER NOT NULL,
        following_id INTEGER NOT NULL,
        UNIQUE(follower_id, following_id)
      )`,

      `CREATE TABLE IF NOT EXISTS stories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT DEFAULT '',
        media_url TEXT DEFAULT '',
        media_type TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS reels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        caption TEXT DEFAULT '',
        media_url TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT DEFAULT '',
        is_group INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS chat_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(chat_id, user_id)
      )`,

      `CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT DEFAULT '',
        media_url TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`,

      `CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        actor_id INTEGER,
        type TEXT NOT NULL,
        post_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_read INTEGER DEFAULT 0
      )`

    ];

    for (const sql of statements) {
      await env.DB.prepare(sql).run();
    }

    /*
      Existing Zilnet databases may have been created with
      the original smaller users/posts tables.

      Add missing columns safely.
    */

    await addColumnIfMissing(
      env,
      "users",
      "display_name",
      "TEXT"
    );

    await addColumnIfMissing(
      env,
      "users",
      "password_hash",
      "TEXT"
    );

    await addColumnIfMissing(
      env,
      "users",
      "password_salt",
      "TEXT"
    );

    await addColumnIfMissing(
      env,
      "users",
      "bio",
      "TEXT DEFAULT ''"
    );

    await addColumnIfMissing(
      env,
      "users",
      "avatar_url",
      "TEXT DEFAULT ''"
    );

    await addColumnIfMissing(
      env,
      "users",
      "skills",
      "TEXT DEFAULT ''"
    );

    await addColumnIfMissing(
      env,
      "users",
      "is_private",
      "INTEGER DEFAULT 0"
    );

    await addColumnIfMissing(
      env,
      "posts",
      "media_url",
      "TEXT DEFAULT ''"
    );

    await addColumnIfMissing(
      env,
      "posts",
      "media_type",
      "TEXT DEFAULT ''"
    );

  })();

  return schemaPromise;
}


async function addColumnIfMissing(
  env,
  table,
  column,
  definition
) {
  const result = await env.DB
    .prepare(`PRAGMA table_info(${table})`)
    .all();

  const exists = (result.results || [])
    .some(row => row.name === column);

  if (!exists) {
    await env.DB
      .prepare(
        `ALTER TABLE ${table}
         ADD COLUMN ${column} ${definition}`
      )
      .run();
  }
}


/* =========================================================
   API ROUTER
   ========================================================= */

async function handleAPI(request, env, url) {

  const path =
    url.pathname.replace(/^\/api/, "") || "/";

  const method =
    request.method.toUpperCase();


  /* ---------- TEST ---------- */

  if (
    path === "/test-db" &&
    method === "GET"
  ) {
    const result = await env.DB
      .prepare("SELECT 1 AS ok")
      .first();

    return json({
      ok: result?.ok === 1
    });
  }


  /* ---------- AUTH ---------- */

  if (
    path === "/signup" &&
    method === "POST"
  ) {
    return signup(request, env);
  }

  if (
    path === "/login" &&
    method === "POST"
  ) {
    return login(request, env);
  }

  if (
    path === "/logout" &&
    method === "POST"
  ) {
    return logout(request, env);
  }

  if (
    path === "/me" &&
    method === "GET"
  ) {
    const user = await requireUser(request, env);

    if (!user) {
      return json({
        user: null
      });
    }

    return json({
      user: cleanUser(user)
    });
  }


  /* ---------- FEED ---------- */

  if (
    path === "/feed" &&
    method === "GET"
  ) {
    return getFeed(request, env);
  }


  /* ---------- POSTS ---------- */

  if (
    path === "/posts" &&
    method === "POST"
  ) {
    return createPost(request, env);
  }

  if (
    path.startsWith("/posts/") &&
    path.endsWith("/like") &&
    method === "POST"
  ) {
    const id =
      path.split("/")[2];

    return toggleLike(
      request,
      env,
      id
    );
  }

  if (
    path.startsWith("/posts/") &&
    path.endsWith("/comments") &&
    method === "GET"
  ) {
    const id =
      path.split("/")[2];

    return getComments(
      request,
      env,
      id
    );
  }

  if (
    path.startsWith("/posts/") &&
    path.endsWith("/comments") &&
    method === "POST"
  ) {
    const id =
      path.split("/")[2];

    return createComment(
      request,
      env,
      id
    );
  }

  if (
    path.startsWith("/posts/") &&
    method === "DELETE"
  ) {
    const id =
      path.split("/")[2];

    return deletePost(
      request,
      env,
      id
    );
  }


  /* ---------- SEARCH ---------- */

  if (
    path === "/search" &&
    method === "GET"
  ) {
    return search(request, env, url);
  }


  /* ---------- FOLLOW ---------- */

  if (
    path.startsWith("/users/") &&
    path.endsWith("/follow") &&
    method === "POST"
  ) {
    const username =
      path.split("/")[2];

    return followUser(
      request,
      env,
      username
    );
  }


  /* ---------- USER PROFILE ---------- */

  if (
    path.startsWith("/users/") &&
    method === "GET"
  ) {
    const username =
      path.split("/")[2];

    return getUserProfile(
      env,
      username
    );
  }


  /* ---------- PROFILE ---------- */

  if (
    path === "/profile" &&
    method === "PUT"
  ) {
    return updateProfile(
      request,
      env
    );
  }


  /* ---------- STORIES ---------- */

  if (
    path === "/stories" &&
    method === "GET"
  ) {
    return getStories(
      request,
      env
    );
  }

  if (
    path === "/stories" &&
    method === "POST"
  ) {
    return createStory(
      request,
      env
    );
  }


  /* ---------- REELS ---------- */

  if (
    path === "/reels" &&
    method === "GET"
  ) {
    return getReels(
      request,
      env
    );
  }

  if (
    path === "/reels" &&
    method === "POST"
  ) {
    return createReel(
      request,
      env
    );
  }


  /* ---------- CHATS ---------- */

  if (
    path === "/chats" &&
    method === "GET"
  ) {
    return getChats(
      request,
      env
    );
  }

  if (
    path === "/chats" &&
    method === "POST"
  ) {
    return createChat(
      request,
      env
    );
  }


  /* ---------- MESSAGES ---------- */

  if (
    path.startsWith("/chats/") &&
    path.endsWith("/messages") &&
    method === "GET"
  ) {
    const chatId =
      path.split("/")[2];

    return getMessages(
      request,
      env,
      chatId
    );
  }

  if (
    path.startsWith("/chats/") &&
    path.endsWith("/messages") &&
    method === "POST"
  ) {
    const chatId =
      path.split("/")[2];

    return sendMessage(
      request,
      env,
      chatId
    );
  }


  /* ---------- NOTIFICATIONS ---------- */

  if (
    path === "/notifications" &&
    method === "GET"
  ) {
    return getNotifications(
      request,
      env
    );
  }


  /* ---------- PRIVACY ---------- */

  if (
    path === "/settings/privacy" &&
    (method === "GET" || method === "POST" || method === "PUT")
  ) {
    if (method === "GET") {
      return getPrivacy(
        request,
        env
      );
    }

    return savePrivacy(
      request,
      env
    );
  }


  /* ---------- MEDIA ---------- */

  if (
    path === "/upload" &&
    method === "POST"
  ) {
    return uploadMedia(
      request,
      env
    );
  }


  return json({
    error: "API route not found."
  }, 404);
}


/* =========================================================
   AUTH
   ========================================================= */

async function signup(request, env) {

  const body =
    await request.json();

  const username =
    String(body.username || "")
      .trim()
      .toLowerCase();

  const password =
    String(body.password || "");

  const displayName =
    String(
      body.display_name ||
      username
    ).trim();

  const email =
    body.email
      ? String(body.email).trim()
      : null;

  if (
    !username ||
    !password
  ) {
    return json({
      error: "Username and password are required."
    }, 400);
  }

  if (!/^[a-z0-9_.]{3,30}$/.test(username)) {
    return json({
      error:
        "Username must be 3–30 characters and use letters, numbers, underscores or dots."
    }, 400);
  }

  if (password.length < 8) {
    return json({
      error:
        "Password must be at least 8 characters."
    }, 400);
  }

  const existing =
    await env.DB
      .prepare(
        `SELECT id
         FROM users
         WHERE username = ?`
      )
      .bind(username)
      .first();

  if (existing) {
    return json({
      error: "Username is already taken."
    }, 409);
  }

  const {
    hash,
    salt
  } = await hashPassword(password);

  let result;

  try {
    result =
      await env.DB
        .prepare(
          `INSERT INTO users
           (
             username,
             email,
             display_name,
             password_hash,
             password_salt
           )
           VALUES (?, ?, ?, ?, ?)`
        )
        .bind(
          username,
          email,
          displayName,
          hash,
          salt
        )
        .run();

  } catch (error) {
    return json({
      error:
        "Could not create the account."
    }, 400);
  }

  const user =
    await env.DB
      .prepare(
        `SELECT *
         FROM users
         WHERE id = ?`
      )
      .bind(result.meta.last_row_id)
      .first();

  const token =
    await createSession(
      env,
      user.id
    );

  return new Response(
    JSON.stringify({
      user: cleanUser(user)
    }),
    {
      headers: {
        "Content-Type":
          "application/json",
        "Set-Cookie":
          sessionCookie(token)
      }
    }
  );
}


async function login(request, env) {

  const body =
    await request.json();

  const username =
    String(body.username || "")
      .trim()
      .toLowerCase();

  const password =
    String(body.password || "");

  if (
    !username ||
    !password
  ) {
    return json({
      error:
        "Username and password are required."
    }, 400);
  }

  const user =
    await env.DB
      .prepare(
        `SELECT *
         FROM users
         WHERE username = ?`
      )
      .bind(username)
      .first();

  if (
    !user ||
    !user.password_hash ||
    !user.password_salt
  ) {
    return json({
      error:
        "Invalid username or password."
    }, 401);
  }

  const valid =
    await verifyPassword(
      password,
      user.password_hash,
      user.password_salt
    );

  if (!valid) {
    return json({
      error:
        "Invalid username or password."
    }, 401);
  }

  const token =
    await createSession(
      env,
      user.id
    );

  return new Response(
    JSON.stringify({
      user: cleanUser(user)
    }),
    {
      headers: {
        "Content-Type":
          "application/json",
        "Set-Cookie":
          sessionCookie(token)
      }
    }
  );
}


async function logout(request, env) {

  const token =
    getCookie(
      request,
      "zilnet_session"
    );

  if (token) {
    await env.DB
      .prepare(
        `DELETE FROM sessions
         WHERE token = ?`
      )
      .bind(token)
      .run();
  }

  return new Response(
    JSON.stringify({
      ok: true
    }),
    {
      headers: {
        "Content-Type":
          "application/json",
        "Set-Cookie":
          "zilnet_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
      }
    }
  );
}


/* =========================================================
   PASSWORD HASHING
   ========================================================= */

async function hashPassword(password) {

  const saltBytes =
    crypto.getRandomValues(
      new Uint8Array(16)
    );

  const salt =
    bytesToBase64(saltBytes);

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

  return {
    hash:
      bytesToBase64(
        new Uint8Array(bits)
      ),
    salt
  };
}


async function verifyPassword(
  password,
  storedHash,
  storedSalt
) {
  const saltBytes =
    base64ToBytes(storedSalt);

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

  return storedHash ===
    bytesToBase64(
      new Uint8Array(bits)
    );
}


/* =========================================================
   SESSIONS
   ========================================================= */

async function createSession(env, userId) {

  const bytes =
    crypto.getRandomValues(
      new Uint8Array(32)
    );

  const token =
    bytesToBase64(bytes);

  const expires =
    Date.now() +
    1000 * 60 * 60 * 24 * 30;

  await env.DB
    .prepare(
      `INSERT INTO sessions
       (user_id, token, expires_at)
       VALUES (?, ?, ?)`
    )
    .bind(
      userId,
      token,
      expires
    )
    .run();

  return token;
}


async function requireUser(
  request,
  env
) {
  const token =
    getCookie(
      request,
      "zilnet_session"
    );

  if (!token) return null;

  const row =
    await env.DB
      .prepare(
        `SELECT users.*
         FROM sessions
         JOIN users
           ON users.id = sessions.user_id
         WHERE sessions.token = ?
           AND sessions.expires_at > ?`
      )
      .bind(
        token,
        Date.now()
      )
      .first();

  return row || null;
}


function getCookie(
  request,
  name
) {
  const header =
    request.headers.get("Cookie") ||
    "";

  const parts =
    header.split(";");

  for (const part of parts) {
    const [key, ...rest] =
      part.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}


function sessionCookie(token) {
  return [
    `zilnet_session=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=2592000"
  ].join("; ");
}


/* =========================================================
   FEED
   ========================================================= */

async function getFeed(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  const viewerId =
    user?.id || 0;

  const result =
    await env.DB
      .prepare(
        `SELECT
          posts.id,
          posts.content,
          posts.media_url,
          posts.media_type,
          posts.created_at,

          users.id AS user_id,
          users.username,
          users.display_name,
          users.avatar_url,

          (
            SELECT COUNT(*)
            FROM likes
            WHERE likes.post_id = posts.id
          ) AS likes,

          (
            SELECT COUNT(*)
            FROM comments
            WHERE comments.post_id = posts.id
          ) AS comments,

          EXISTS(
            SELECT 1
            FROM likes
            WHERE likes.post_id = posts.id
              AND likes.user_id = ?
          ) AS liked

        FROM posts

        JOIN users
          ON users.id = posts.user_id

        ORDER BY posts.id DESC

        LIMIT 100`
      )
      .bind(viewerId)
      .all();

  return json({
    posts:
      result.results || []
  });
}


/* =========================================================
   CREATE POST
   ========================================================= */

async function createPost(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const body =
    await request.json();

  const content =
    String(body.content || "")
      .trim();

  const mediaUrl =
    String(body.media_url || "");

  const mediaType =
    String(body.media_type || "");

  if (
    !content &&
    !mediaUrl
  ) {
    return json({
      error:
        "Write something or add media."
    }, 400);
  }

  if (content.length > 5000) {
    return json({
      error:
        "Post is too long."
    }, 400);
  }

  const result =
    await env.DB
      .prepare(
        `INSERT INTO posts
         (
           user_id,
           content,
           media_url,
           media_type
         )
         VALUES (?, ?, ?, ?)`
      )
      .bind(
        user.id,
        content,
        mediaUrl,
        mediaType
      )
      .run();

  return json({
    ok: true,
    post_id:
      result.meta.last_row_id
  });
}


/* =========================================================
   LIKE
   ========================================================= */

async function toggleLike(
  request,
  env,
  postId
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const existing =
    await env.DB
      .prepare(
        `SELECT id
         FROM likes
         WHERE post_id = ?
           AND user_id = ?`
      )
      .bind(
        postId,
        user.id
      )
      .first();

  if (existing) {

    await env.DB
      .prepare(
        `DELETE FROM likes
         WHERE id = ?`
      )
      .bind(existing.id)
      .run();

  } else {

    await env.DB
      .prepare(
        `INSERT OR IGNORE INTO likes
         (post_id, user_id)
         VALUES (?, ?)`
      )
      .bind(
        postId,
        user.id
      )
      .run();
  }

  const count =
    await env.DB
      .prepare(
        `SELECT COUNT(*) AS count
         FROM likes
         WHERE post_id = ?`
      )
      .bind(postId)
      .first();

  return json({
    liked: !existing,
    likes:
      count?.count || 0
  });
}


/* =========================================================
   COMMENTS
   ========================================================= */

async function getComments(
  request,
  env,
  postId
) {
  const result =
    await env.DB
      .prepare(
        `SELECT
          comments.id,
          comments.content,
          comments.created_at,
          users.username,
          users.display_name,
          users.avatar_url
         FROM comments
         JOIN users
           ON users.id = comments.user_id
         WHERE comments.post_id = ?
         ORDER BY comments.id ASC`
      )
      .bind(postId)
      .all();

  return json({
    comments:
      result.results || []
  });
}


async function createComment(
  request,
  env,
  postId
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const body =
    await request.json();

  const content =
    String(body.content || "")
      .trim();

  if (!content) {
    return json({
      error:
        "Comment cannot be empty."
    }, 400);
  }

  if (content.length > 1000) {
    return json({
      error:
        "Comment is too long."
    }, 400);
  }

  await env.DB
    .prepare(
      `INSERT INTO comments
       (post_id, user_id, content)
       VALUES (?, ?, ?)`
    )
    .bind(
      postId,
      user.id,
      content
    )
    .run();

  return json({
    ok: true
  });
}


/* =========================================================
   DELETE POST
   ========================================================= */

async function deletePost(
  request,
  env,
  postId
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const post =
    await env.DB
      .prepare(
        `SELECT user_id, media_url
         FROM posts
         WHERE id = ?`
      )
      .bind(postId)
      .first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  if (post.user_id !== user.id) {
    return json({
      error: "You cannot delete this post."
    }, 403);
  }

  await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM likes
       WHERE post_id = ?`
    ).bind(postId),

    env.DB.prepare(
      `DELETE FROM comments
       WHERE post_id = ?`
    ).bind(postId),

    env.DB.prepare(
      `DELETE FROM posts
       WHERE id = ?`
    ).bind(postId)
  ]);

  return json({
    ok: true
  });
}


/* =========================================================
   SEARCH
   ========================================================= */

async function search(
  request,
  env,
  url
) {
  const q =
    String(
      url.searchParams.get("q") ||
      ""
    ).trim();

  if (!q) {
    return json({
      users: [],
      posts: []
    });
  }

  const like =
    `%${q}%`;

  const users =
    await env.DB
      .prepare(
        `SELECT
          id,
          username,
          display_name,
          avatar_url,
          bio,
          skills
         FROM users
         WHERE username LIKE ?
            OR display_name LIKE ?
         ORDER BY username
         LIMIT 50`
      )
      .bind(
        like,
        like
      )
      .all();

  const posts =
    await env.DB
      .prepare(
        `SELECT
          posts.id,
          posts.content,
          posts.media_url,
          posts.media_type,
          posts.created_at,
          users.username,
          users.display_name,
          users.avatar_url
         FROM posts
         JOIN users
           ON users.id = posts.user_id
         WHERE posts.content LIKE ?
         ORDER BY posts.id DESC
         LIMIT 50`
      )
      .bind(like)
      .all();

  return json({
    users:
      users.results || [],
    posts:
      posts.results || []
  });
}


/* =========================================================
   FOLLOW
   ========================================================= */

async function followUser(
  request,
  env,
  username
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const target =
    await env.DB
      .prepare(
        `SELECT *
         FROM users
         WHERE username = ?`
      )
      .bind(username)
      .first();

  if (!target) {
    return json({
      error: "User not found."
    }, 404);
  }

  if (target.id === user.id) {
    return json({
      error: "You cannot follow yourself."
    }, 400);
  }

  const existing =
    await env.DB
      .prepare(
        `SELECT id
         FROM follows
         WHERE follower_id = ?
           AND following_id = ?`
      )
      .bind(
        user.id,
        target.id
      )
      .first();

  if (existing) {

    await env.DB
      .prepare(
        `DELETE FROM follows
         WHERE id = ?`
      )
      .bind(existing.id)
      .run();

  } else {

    await env.DB
      .prepare(
        `INSERT OR IGNORE INTO follows
         (follower_id, following_id)
         VALUES (?, ?)`
      )
      .bind(
        user.id,
        target.id
      )
      .run();

    await env.DB
      .prepare(
        `INSERT INTO notifications
         (user_id, actor_id, type)
         VALUES (?, ?, ?)`
      )
      .bind(
        target.id,
        user.id,
        "follow"
      )
      .run();
  }

  return json({
    following: !existing
  });
}


/* =========================================================
   USER PROFILE
   ========================================================= */

async function getUserProfile(
  env,
  username
) {
  const user =
    await env.DB
      .prepare(
        `SELECT
          id,
          username,
          display_name,
          email,
          bio,
          avatar_url,
          skills,
          is_private,
          created_at
         FROM users
         WHERE username = ?`
      )
      .bind(username)
      .first();

  if (!user) {
    return json({
      error: "User not found."
    }, 404);
  }

  const followers =
    await env.DB
      .prepare(
        `SELECT COUNT(*) AS count
         FROM follows
         WHERE following_id = ?`
      )
      .bind(user.id)
      .first();

  const following =
    await env.DB
      .prepare(
        `SELECT COUNT(*) AS count
         FROM follows
         WHERE follower_id = ?`
      )
      .bind(user.id)
      .first();

  return json({
    user,
    followers:
      followers?.count || 0,
    following:
      following?.count || 0
  });
}


/* =========================================================
   PROFILE UPDATE
   ========================================================= */

async function updateProfile(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const body =
    await request.json();

  const displayName =
    String(
      body.display_name ??
      user.display_name ??
      user.username
    ).trim();

  const bio =
    String(
      body.bio ??
      user.bio ??
      ""
    ).trim();

  const skills =
    String(
      body.skills ??
      user.skills ??
      ""
    ).trim();

  const avatarUrl =
    String(
      body.avatar_url ??
      user.avatar_url ??
      ""
    ).trim();

  if (displayName.length > 80) {
    return json({
      error:
        "Display name is too long."
    }, 400);
  }

  if (bio.length > 500) {
    return json({
      error:
        "Bio is too long."
    }, 400);
  }

  await env.DB
    .prepare(
      `UPDATE users
       SET
         display_name = ?,
         bio = ?,
         skills = ?,
         avatar_url = ?
       WHERE id = ?`
    )
    .bind(
      displayName,
      bio,
      skills,
      avatarUrl,
      user.id
    )
    .run();

  return json({
    ok: true
  });
}


/* =========================================================
   STORIES
   ========================================================= */

async function getStories(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  const viewerId =
    user?.id || 0;

  const result =
    await env.DB
      .prepare(
        `SELECT
          stories.id,
          stories.content,
          stories.media_url,
          stories.media_type,
          stories.created_at,
          users.username,
          users.display_name,
          users.avatar_url
         FROM stories
         JOIN users
           ON users.id = stories.user_id
         WHERE
           stories.created_at >=
           datetime('now', '-24 hours')
         ORDER BY stories.id DESC`
      )
      .all();

  return json({
    stories:
      result.results || []
  });
}


async function createStory(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const body =
    await request.json();

  const content =
    String(body.content || "")
      .trim();

  const mediaUrl =
    String(body.media_url || "");

  const mediaType =
    String(body.media_type || "");

  if (
    !content &&
    !mediaUrl
  ) {
    return json({
      error:
        "Story cannot be empty."
    }, 400);
  }

  await env.DB
    .prepare(
      `INSERT INTO stories
       (
         user_id,
         content,
         media_url,
         media_type
       )
       VALUES (?, ?, ?, ?)`
    )
    .bind(
      user.id,
      content,
      mediaUrl,
      mediaType
    )
    .run();

  return json({
    ok: true
  });
}


/* =========================================================
   REELS
   ========================================================= */

async function getReels(
  request,
  env
) {
  const result =
    await env.DB
      .prepare(
        `SELECT
          reels.id,
          reels.caption,
          reels.media_url,
          reels.created_at,
          users.username,
          users.display_name,
          users.avatar_url
         FROM reels
         JOIN users
           ON users.id = reels.user_id
         ORDER BY reels.id DESC
         LIMIT 100`
      )
      .all();

  return json({
    reels:
      result.results || []
  });
}


async function createReel(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const body =
    await request.json();

  const mediaUrl =
    String(body.media_url || "")
      .trim();

  const caption =
    String(body.caption || "")
      .trim();

  if (!mediaUrl) {
    return json({
      error:
        "Reel media is required."
    }, 400);
  }

  await env.DB
    .prepare(
      `INSERT INTO reels
       (
         user_id,
         caption,
         media_url
       )
       VALUES (?, ?, ?)`
    )
    .bind(
      user.id,
      caption,
      mediaUrl
    )
    .run();

  return json({
    ok: true
  });
}


/* =========================================================
   CHATS
   ========================================================= */

async function getChats(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const result =
    await env.DB
      .prepare(
        `SELECT
          chats.id,
          chats.name,
          chats.is_group,
          chats.created_at
         FROM chats
         JOIN chat_members
           ON chat_members.chat_id = chats.id
         WHERE chat_members.user_id = ?
         ORDER BY chats.id DESC`
      )
      .bind(user.id)
      .all();

  return json({
    chats:
      result.results || []
  });
}


async function createChat(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const body =
    await request.json();

  const name =
    String(body.name || "")
      .trim();

  const isGroup =
    body.is_group ? 1 : 0;

  const memberIds =
    Array.isArray(body.member_ids)
      ? body.member_ids
      : [];

  const result =
    await env.DB
      .prepare(
        `INSERT INTO chats
         (name, is_group)
         VALUES (?, ?)`
      )
      .bind(
        name,
        isGroup
      )
      .run();

  const chatId =
    result.meta.last_row_id;

  const members =
    new Set([
      user.id,
      ...memberIds
        .map(Number)
        .filter(Boolean)
    ]);

  for (const memberId of members) {
    await env.DB
      .prepare(
        `INSERT OR IGNORE INTO chat_members
         (chat_id, user_id)
         VALUES (?, ?)`
      )
      .bind(
        chatId,
        memberId
      )
      .run();
  }

  return json({
    ok: true,
    chat_id: chatId
  });
}


/* =========================================================
   MESSAGES
   ========================================================= */

async function getMessages(
  request,
  env,
  chatId
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const member =
    await env.DB
      .prepare(
        `SELECT id
         FROM chat_members
         WHERE chat_id = ?
           AND user_id = ?`
      )
      .bind(
        chatId,
        user.id
      )
      .first();

  if (!member) {
    return json({
      error:
        "You are not a member of this chat."
    }, 403);
  }

  const result =
    await env.DB
      .prepare(
        `SELECT
          messages.id,
          messages.content,
          messages.media_url,
          messages.created_at,
          users.username,
          users.display_name,
          users.avatar_url
         FROM messages
         JOIN users
           ON users.id = messages.user_id
         WHERE messages.chat_id = ?
         ORDER BY messages.id ASC
         LIMIT 500`
      )
      .bind(chatId)
      .all();

  return json({
    messages:
      result.results || []
  });
}


async function sendMessage(
  request,
  env,
  chatId
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const member =
    await env.DB
      .prepare(
        `SELECT id
         FROM chat_members
         WHERE chat_id = ?
           AND user_id = ?`
      )
      .bind(
        chatId,
        user.id
      )
      .first();

  if (!member) {
    return json({
      error:
        "You are not a member of this chat."
    }, 403);
  }

  const body =
    await request.json();

  const content =
    String(body.content || "")
      .trim();

  const mediaUrl =
    String(body.media_url || "")
      .trim();

  if (
    !content &&
    !mediaUrl
  ) {
    return json({
      error:
        "Message cannot be empty."
    }, 400);
  }

  const result =
    await env.DB
      .prepare(
        `INSERT INTO messages
         (
           chat_id,
           user_id,
           content,
           media_url
         )
         VALUES (?, ?, ?, ?)`
      )
      .bind(
        chatId,
        user.id,
        content,
        mediaUrl
      )
      .run();

  return json({
    ok: true,
    message_id:
      result.meta.last_row_id
  });
}


/* =========================================================
   NOTIFICATIONS
   ========================================================= */

async function getNotifications(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const result =
    await env.DB
      .prepare(
        `SELECT
          notifications.id,
          notifications.type,
          notifications.post_id,
          notifications.created_at,
          notifications.is_read,

          users.username AS actor_username,
          users.display_name AS actor_display_name,
          users.avatar_url AS actor_avatar

         FROM notifications

         LEFT JOIN users
           ON users.id = notifications.actor_id

         WHERE notifications.user_id = ?

         ORDER BY notifications.id DESC

         LIMIT 100`
      )
      .bind(user.id)
      .all();

  return json({
    notifications:
      result.results || []
  });
}


/* =========================================================
   PRIVACY
   ========================================================= */

async function getPrivacy(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  return json({
    is_private:
      Boolean(user.is_private)
  });
}


async function savePrivacy(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  const body =
    await request.json();

  const isPrivate =
    body.is_private ? 1 : 0;

  await env.DB
    .prepare(
      `UPDATE users
       SET is_private = ?
       WHERE id = ?`
    )
    .bind(
      isPrivate,
      user.id
    )
    .run();

  return json({
    ok: true,
    is_private:
      Boolean(isPrivate)
  });
}


/* =========================================================
   R2 MEDIA UPLOAD
   ========================================================= */

async function uploadMedia(
  request,
  env
) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error: "Please log in."
    }, 401);
  }

  if (!env.MEDIA) {
    return json({
      error:
        "R2 media storage is not configured."
    }, 500);
  }

  const form =
    await request.formData();

  const file =
    form.get("file");

  const type =
    String(
      form.get("type") ||
      "media"
    );

  if (
    !file ||
    typeof file === "string"
  ) {
    return json({
      error:
        "No media file received."
    }, 400);
  }

  const allowed =
    [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
      "video/mp4",
      "video/webm",
      "video/quicktime"
    ];

  if (!allowed.includes(file.type)) {
    return json({
      error:
        "Unsupported media type."
    }, 400);
  }

  if (file.size > 50 * 1024 * 1024) {
    return json({
      error:
        "Maximum file size is 50 MB."
    }, 400);
  }

  const extension =
    extensionFromType(
      file.type
    );

  const key =
    `${type}/${user.id}/` +
    `${crypto.randomUUID()}` +
    `.${extension}`;

  await env.MEDIA.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType:
          file.type
      }
    }
  );

  const publicUrl =
    `/media/${encodeURIComponent(key)}`;

  return json({
    ok: true,
    url: publicUrl,
    media_url: publicUrl,
    media_type: file.type
  });
}


/* =========================================================
   R2 MEDIA SERVING
   ========================================================= */

async function handleMedia(
  request,
  env,
  url
) {
  if (!env.MEDIA) {
    return text(
      "Media storage is not configured.",
      500
    );
  }

  const key =
    decodeURIComponent(
      url.pathname
        .replace(/^\/media\//, "")
    );

  if (!key) {
    return text(
      "Media not found.",
      404
    );
  }

  const object =
    await env.MEDIA.get(key);

  if (!object) {
    return text(
      "Media not found.",
      404
    );
  }

  const headers =
    new Headers();

  object.writeHttpMetadata(
    headers
  );

  headers.set(
    "ETag",
    object.httpEtag
  );

  headers.set(
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  return new Response(
    object.body,
    {
      headers
    }
  );
}


/* =========================================================
   USER CLEANING
   ========================================================= */

function cleanUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    username: user.username,
    email: user.email || null,
    display_name:
      user.display_name ||
      user.username,
    bio: user.bio || "",
    avatar_url:
      user.avatar_url || "",
    skills:
      user.skills || "",
    is_private:
      Boolean(user.is_private),
    created_at:
      user.created_at
  };
}


/* =========================================================
   BASE64 HELPERS
   ========================================================= */

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}


function base64ToBytes(base64) {
  const binary =
    atob(base64);

  const bytes =
    new Uint8Array(
      binary.length
    );

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}


function extensionFromType(type) {

  const map = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov"
  };

  return map[type] || "bin";
}
