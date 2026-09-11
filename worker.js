const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 120000;

/* -------------------------
   RESPONSE HELPERS
------------------------- */

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type, authorization",
      ...extra
    }
  });
}

function text(data, status = 200) {
  return new Response(data, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "access-control-allow-origin": "*"
    }
  });
}

/* -------------------------
   GENERAL HELPERS
------------------------- */

function nowISO() {
  return new Date().toISOString();
}

function nowMs() {
  return Date.now();
}

function uuid() {
  return crypto.randomUUID();
}

function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function safeUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function cleanDisplayName(value) {
  return String(value || "").trim();
}

function cleanEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validUsername(username) {
  return /^[a-zA-Z0-9_.]{3,30}$/.test(username);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* -------------------------
   PASSWORD HASHING
------------------------- */

/*
  New password format:

  pbkdf2$sha256$iterations$salt$hash
*/

async function hashPassword(password) {
  const salt = randomBytes(16);

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
      hash: "SHA-256",
      salt,
      iterations: PASSWORD_ITERATIONS
    },
    key,
    256
  );

  const hash = new Uint8Array(bits);

  return {
    password_hash:
      `pbkdf2$sha256$${PASSWORD_ITERATIONS}$` +
      `${bytesToBase64(salt)}$${bytesToBase64(hash)}`,

    password_salt: bytesToBase64(salt)
  };
}

function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array)) {
    a = new Uint8Array(a);
  }

  if (!(b instanceof Uint8Array)) {
    b = new Uint8Array(b);
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function verifyPBKDF2(password, stored) {
  try {
    const parts = String(stored || "").split("$");

    if (parts.length !== 5) {
      return false;
    }

    const [
      algorithm,
      hashName,
      iterationsString,
      saltString,
      hashString
    ] = parts;

    if (
      algorithm !== "pbkdf2" ||
      hashName !== "sha256"
    ) {
      return false;
    }

    const iterations = Number(iterationsString);

    if (
      !Number.isSafeInteger(iterations) ||
      iterations < 1000 ||
      iterations > 10000000
    ) {
      return false;
    }

    const salt = base64ToBytes(saltString);
    const expected = base64ToBytes(hashString);

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
        hash: "SHA-256",
        salt,
        iterations
      },
      key,
      expected.length * 8
    );

    return constantTimeEqual(
      new Uint8Array(bits),
      expected
    );
  } catch {
    return false;
  }
}

/* -------------------------
   LEGACY PASSWORD SUPPORT
------------------------- */

/*
  IMPORTANT:

  Existing users may have the old password format.

  We intentionally keep this function separate so the exact
  legacy algorithm can be plugged in without touching existing
  accounts or passwords.

  Until the original hashing formula is identified, this does
  NOT guess an algorithm.
*/

async function verifyLegacyPassword(
  password,
  passwordHash,
  passwordSalt
) {
  /*
    Legacy compatibility will be added here after identifying
    the original hashing method.

    Returning false is intentional for now.
  */

  return false;
}

async function verifyPassword(user, password) {
  if (!password) {
    return {
      valid: false,
      legacy: false
    };
  }

  const stored = String(user.password_hash || "");

  /* New PBKDF2 account */
  if (stored.startsWith("pbkdf2$")) {
    return {
      valid: await verifyPBKDF2(password, stored),
      legacy: false
    };
  }

  /* Existing/legacy account */
  const legacyValid = await verifyLegacyPassword(
    password,
    stored,
    String(user.password_salt || "")
  );

  return {
    valid: legacyValid,
    legacy: legacyValid
  };
}

/* -------------------------
   DATABASE HELPERS
------------------------- */

async function getUserById(env, id) {
  return await env.DB
    .prepare(`
      SELECT
        id,
        username,
        email,
        created_at,
        display_name,
        bio,
        avatar_url,
        skills,
        password_hash,
        password_salt,
        is_private
      FROM users
      WHERE id = ?
      LIMIT 1
    `)
    .bind(id)
    .first();
}

async function getUserByUsername(env, username) {
  return await env.DB
    .prepare(`
      SELECT
        id,
        username,
        email,
        created_at,
        display_name,
        bio,
        avatar_url,
        skills,
        password_hash,
        password_salt,
        is_private
      FROM users
      WHERE lower(username) = lower(?)
      LIMIT 1
    `)
    .bind(username)
    .first();
}

async function getUserByEmail(env, email) {
  return await env.DB
    .prepare(`
      SELECT
        id,
        username,
        email,
        created_at,
        display_name,
        bio,
        avatar_url,
        skills,
        password_hash,
        password_salt,
        is_private
      FROM users
      WHERE lower(email) = lower(?)
      LIMIT 1
    `)
    .bind(email)
    .first();
}

/* -------------------------
   USER CREATION
------------------------- */

async function createUser(env, {
  username,
  email,
  display_name,
  password_hash,
  password_salt
}) {
  const result = await env.DB
    .prepare(`
      INSERT INTO users (
        username,
        email,
        display_name,
        bio,
        avatar_url,
        skills,
        password_hash,
        password_salt,
        is_private
      )
      VALUES (?, ?, ?, '', '', '', ?, ?, 0)
    `)
    .bind(
      username,
      email,
      display_name,
      password_hash,
      password_salt
    )
    .run();

  if (!result.success) {
    throw new Error("USER_INSERT_FAILED");
  }

  return await getUserByUsername(env, username);
}

/* -------------------------
   USER SETTINGS
------------------------- */

async function ensureSettings(env, userId) {
  await env.DB
    .prepare(`
      INSERT OR IGNORE INTO user_settings (
        user_id,
        theme,
        profile_visibility,
        message_privacy,
        notification_settings
      )
      VALUES (?, 'system', 'public', 'everyone', '{}')
    `)
    .bind(String(userId))
    .run();
}

async function getSettings(env, userId) {
  const settings = await env.DB
    .prepare(`
      SELECT
        user_id,
        theme,
        profile_visibility,
        message_privacy,
        notification_settings
      FROM user_settings
      WHERE user_id = ?
      LIMIT 1
    `)
    .bind(String(userId))
    .first();

  return settings || {
    user_id: String(userId),
    theme: "system",
    profile_visibility: "public",
    message_privacy: "everyone",
    notification_settings: "{}"
  };
}
/* =========================
   PART 2 — SESSIONS + AUTH
========================= */

/* -------------------------
   SESSION TOKEN
------------------------- */

async function hashToken(token) {
  const data = new TextEncoder().encode(token);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return bytesToHex(new Uint8Array(digest));
}

async function createSession(env, userId) {
  const tokenBytes = randomBytes(32);
  const token = bytesToBase64(tokenBytes);
  const tokenHash = await hashToken(token);

  const createdAt = nowISO();
  const expiresAt =
    nowMs() + SESSION_DAYS * 24 * 60 * 60 * 1000;

  await env.DB
    .prepare(`
      INSERT INTO sessions (
        user_id,
        token,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?)
    `)
    .bind(
      Number(userId),
      token,
      expiresAt,
      createdAt
    )
    .run();

  return token;
}

async function getSessionUser(env, request) {
  const auth = request.headers.get("Authorization") || "";

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  const token = auth.slice(7).trim();

  if (!token) {
    return null;
  }

  const session = await env.DB
    .prepare(`
      SELECT
        s.id AS session_id,
        s.user_id,
        s.expires_at,
        u.id,
        u.username,
        u.email,
        u.created_at,
        u.display_name,
        u.bio,
        u.avatar_url,
        u.skills,
        u.is_private,
        u.password_hash,
        u.password_salt
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
        AND s.expires_at > ?
      LIMIT 1
    `)
    .bind(token, nowMs())
    .first();

  if (!session) {
    return null;
  }

  return session;
}

async function deleteSession(env, request) {
  const auth = request.headers.get("Authorization") || "";

  if (!auth.startsWith("Bearer ")) {
    return;
  }

  const token = auth.slice(7).trim();

  if (!token) {
    return;
  }

  await env.DB
    .prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `)
    .bind(token)
    .run();
}

/* -------------------------
   PUBLIC USER RESPONSE
------------------------- */

function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    username: user.username,
    email: user.email || "",
    display_name: user.display_name || "",
    bio: user.bio || "",
    avatar_url: user.avatar_url || "",
    skills: user.skills || "",
    is_private: Number(user.is_private || 0),
    created_at: user.created_at || ""
  };
}

/* -------------------------
   SIGNUP
------------------------- */

async function signup(env, request) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      error: "Invalid JSON"
    }, 400);
  }

  const username = safeUsername(body.username);
  const email = cleanEmail(body.email);
  const displayName =
    cleanDisplayName(body.display_name) || username;
  const password = String(body.password || "");

  if (!validUsername(username)) {
    return json({
      error:
        "Username must be 3-30 characters and use only letters, numbers, underscores or dots."
    }, 400);
  }

  if (!validEmail(email)) {
    return json({
      error: "Please enter a valid email."
    }, 400);
  }

  if (password.length < 8) {
    return json({
      error: "Password must be at least 8 characters."
    }, 400);
  }

  const existingUsername =
    await getUserByUsername(env, username);

  if (existingUsername) {
    return json({
      error: "Username already exists."
    }, 409);
  }

  const existingEmail =
    await getUserByEmail(env, email);

  if (existingEmail) {
    return json({
      error: "Email already exists."
    }, 409);
  }

  try {
    const passwordData =
      await hashPassword(password);

    const user = await createUser(env, {
      username,
      email,
      display_name: displayName,
      password_hash: passwordData.password_hash,
      password_salt: passwordData.password_salt
    });

    if (!user) {
      throw new Error("USER_CREATION_FAILED");
    }

    await ensureSettings(env, user.id);

    const token =
      await createSession(env, user.id);

    return json({
      success: true,
      user: publicUser(user),
      token
    }, 201);

  } catch (error) {
    console.error(
      "SIGNUP_ERROR",
      error?.message || error
    );

    return json({
      error: "Unable to create account."
    }, 500);
  }
}

/* -------------------------
   LOGIN
------------------------- */

async function login(env, request) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      error: "Invalid JSON"
    }, 400);
  }

  const identifier =
    String(
      body.identifier ??
      body.username ??
      body.email ??
      ""
    ).trim();

  const password =
    String(body.password || "");

  if (!identifier || !password) {
    return json({
      error: "Username/email and password are required."
    }, 400);
  }

  let user = null;

  if (identifier.includes("@")) {
    user = await getUserByEmail(
      env,
      cleanEmail(identifier)
    );
  } else {
    user = await getUserByUsername(
      env,
      safeUsername(identifier)
    );
  }

  if (!user) {
    return json({
      error: "Invalid user or password."
    }, 401);
  }

  const result =
    await verifyPassword(user, password);

  if (!result.valid) {
    return json({
      error: "Invalid user or password."
    }, 401);
  }

  /*
    If an old password was successfully verified,
    upgrade it to the new PBKDF2 format.

    This means the user keeps using the SAME password.
  */

  if (result.legacy) {
    try {
      const newPassword =
        await hashPassword(password);

      await env.DB
        .prepare(`
          UPDATE users
          SET
            password_hash = ?,
            password_salt = ?
          WHERE id = ?
        `)
        .bind(
          newPassword.password_hash,
          newPassword.password_salt,
          user.id
        )
        .run();

      user.password_hash =
        newPassword.password_hash;

      user.password_salt =
        newPassword.password_salt;

    } catch (error) {
      /*
        Login should still succeed even if the
        password-upgrade write fails.
      */

      console.error(
        "PASSWORD_UPGRADE_ERROR",
        error?.message || error
      );
    }
  }

  await ensureSettings(env, user.id);

  const token =
    await createSession(env, user.id);

  return json({
    success: true,
    user: publicUser(user),
    token
  });
}

/* -------------------------
   CURRENT USER
------------------------- */

async function currentUser(env, request) {
  const user =
    await getSessionUser(env, request);

  if (!user) {
    return json({
      error: "Session expired."
    }, 401);
  }

  await ensureSettings(env, user.id);

  return json({
    success: true,
    user: publicUser(user),
    settings: await getSettings(env, user.id)
  });
}

/* -------------------------
   LOGOUT
------------------------- */

async function logout(env, request) {
  await deleteSession(env, request);

  return json({
    success: true
  });
}

/* -------------------------
   AUTH ROUTER
------------------------- */

async function handleAuth(env, request, pathname) {

  if (
    pathname === "/api/signup" &&
    request.method === "POST"
  ) {
    return await signup(env, request);
  }

  if (
    pathname === "/api/login" &&
    request.method === "POST"
  ) {
    return await login(env, request);
  }

  if (
    pathname === "/api/me" &&
    request.method === "GET"
  ) {
    return await currentUser(env, request);
  }

  if (
    pathname === "/api/logout" &&
    request.method === "POST"
  ) {
    return await logout(env, request);
  }

  return null;
}
 /* =========================
    PART 3 — WORKER ROUTER
 ========================= */

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  /* -------------------------
     CORS / PREFLIGHT
  ------------------------- */

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods":
          "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "access-control-allow-headers":
          "content-type, authorization",
        "access-control-max-age": "86400"
      }
    });
  }

  /* -------------------------
     API
  ------------------------- */

  if (pathname.startsWith("/api/")) {
    try {
      const authResponse =
        await handleAuth(
          env,
          request,
          pathname
        );

      if (authResponse) {
        return authResponse;
      }

      /* Health check */

      if (
        pathname === "/api/health" &&
        request.method === "GET"
      ) {
        return json({
          success: true,
          service: "zilnet",
          status: "online",
          time: nowISO()
        });
      }

      /* Public profile */

      const profileMatch =
        pathname.match(
          /^\/api\/profile\/([^/]+)$/
        );

      if (
        profileMatch &&
        request.method === "GET"
      ) {
        const username =
          decodeURIComponent(
            profileMatch[1]
          );

        const viewer =
          await getSessionUser(
            env,
            request
          );

        /*
          Keep this endpoint available even
          before the rest of the social API
          is connected.
        */

        const user =
          await getUserByUsername(
            env,
            username
          );

        if (!user) {
          return json({
            error: "User not found"
          }, 404);
        }

        const settings =
          await getSettings(
            env,
            user.id
          );

        const isOwner =
          viewer &&
          String(viewer.id) ===
            String(user.id);

        if (
          settings.profile_visibility ===
            "private" &&
          !isOwner
        ) {
          return json({
            success: true,
            user: publicUser(user),
            private: true,
            posts: []
          });
        }

        return json({
          success: true,
          user: publicUser(user),
          private: false,
          posts: []
        });
      }

      return json({
        error: "API endpoint not found."
      }, 404);

    } catch (error) {
      console.error(
        "API_ERROR",
        error?.stack ||
        error?.message ||
        error
      );

      if (
        error instanceof HttpError
      ) {
        return json({
          error: error.message
        }, error.status);
      }

      return json({
        error: "Internal server error."
      }, 500);
    }
  }

  /* -------------------------
     FRONTEND
  ------------------------- */

  if (
    env.ASSETS &&
    request.method === "GET"
  ) {
    try {
      return await env.ASSETS.fetch(
        request
      );
    } catch (error) {
      console.error(
        "ASSET_ERROR",
        error?.message || error
      );
    }
  }

  return new Response(
    "Zilnet is running.",
    {
      status: 200,
      headers: {
        "content-type":
          "text/plain; charset=utf-8"
      }
    }
  );
}

/* =========================
   CLOUDFLARE ENTRY POINT
========================= */

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(
        request,
        env,
        ctx
      );
    } catch (error) {
      console.error(
        "FATAL_WORKER_ERROR",
        error?.stack ||
        error?.message ||
        error
      );

      return json({
        error: "Internal server error."
      }, 500);
    }
  }
};
