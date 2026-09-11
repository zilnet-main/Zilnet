const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 150000;
const SESSION_COOKIE = "zilnet_session";

const now = () => new Date().toISOString();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function cleanText(value, max = 1000) {
  return String(value ?? "").trim().slice(0, max);
}

function cleanUsername(value) {
  return cleanText(value, 30).toLowerCase();
}

function cleanEmail(value) {
  return cleanText(value, 200).toLowerCase();
}

async function readJSON(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
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

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function sha256(value) {
  const data =
    new TextEncoder().encode(String(value));

  const hash =
    await crypto.subtle.digest("SHA-256", data);

  return bytesToBase64(
    new Uint8Array(hash)
  );
}

function randomToken(length = 48) {
  const bytes =
    crypto.getRandomValues(
      new Uint8Array(length)
    );

  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}


/* ============================================================
   PASSWORD SYSTEM

   This keeps compatibility with your OLD Zilnet passwords.

   Format:
   pbkdf2$150000$SALT$HASH
   ============================================================ */

async function hashPassword(password) {
  const salt =
    crypto.getRandomValues(
      new Uint8Array(16)
    );

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PASSWORD_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      256
    );

  return [
    "pbkdf2",
    PASSWORD_ITERATIONS,
    bytesToBase64(salt),
    bytesToBase64(
      new Uint8Array(bits)
    )
  ].join("$");
}

async function verifyPassword(password, stored) {
  try {
    if (!stored) {
      return false;
    }

    const parts =
      String(stored).split("$");

    if (
      parts.length !== 4 ||
      parts[0] !== "pbkdf2"
    ) {
      return false;
    }

    const iterations =
      Number(parts[1]);

    const salt =
      base64ToBytes(parts[2]);

    const expected =
      base64ToBytes(parts[3]);

    if (
      !Number.isInteger(iterations) ||
      iterations <= 0
    ) {
      return false;
    }

    const key =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

    const bits =
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations,
          hash: "SHA-256"
        },
        key,
        256
      );

    return constantTimeEqual(
      new Uint8Array(bits),
      expected
    );

  } catch (error) {
    console.error(
      "Password verification error:",
      error
    );

    return false;
  }
}


/* ============================================================
   COOKIES
   ============================================================ */

function getCookie(request, name) {
  const header =
    request.headers.get("Cookie") || "";

  for (const part of header.split(";")) {
    const [key, ...rest] =
      part.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

function makeSessionCookie(token) {
  return [
    `${SESSION_COOKIE}=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    `${SESSION_COOKIE}=`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    "Max-Age=0"
  ].join("; ");
}

function withCookie(response, cookie) {
  const headers =
    new Headers(response.headers);

  headers.append(
    "Set-Cookie",
    cookie
  );

  return new Response(
    response.body,
    {
      status: response.status,
      headers
    }
  );
}


/* ============================================================
   USER HELPERS
   ============================================================ */

async function getUserById(id, env) {
  const userId =
    parseInt(id, 10);

  if (
    !Number.isInteger(userId) ||
    userId <= 0
  ) {
    return null;
  }

  return env.DB.prepare(`
    SELECT *
    FROM users
    WHERE id = ?
    LIMIT 1
  `).bind(userId).first();
}

function parseSkills(value) {
  if (!value) {
    return [];
  }

  try {
    const parsed =
      JSON.parse(value);

    return Array.isArray(parsed)
      ? parsed
      : [];
  } catch {
    return String(value)
      .split(",")
      .map(x => x.trim())
      .filter(Boolean);
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name || "",
    email: user.email || "",
    bio: user.bio || "",
    skills: parseSkills(user.skills),
    avatarUrl: user.avatar_url || "",
    isPrivate: !!user.is_private,
    createdAt: user.created_at
  };
}


/* ============================================================
   SESSION
   ============================================================ */

async function createSession(userId, env) {
  const rawToken =
    randomToken(48);

  const tokenHash =
    await sha256(rawToken);

  const expiresAt =
    Date.now() +
    SESSION_DAYS *
    24 *
    60 *
    60 *
    1000;

  await env.DB.prepare(`
    INSERT INTO sessions
    (
      user_id,
      token,
      expires_at
    )
    VALUES (?, ?, ?)
  `).bind(
    Number(userId),
    tokenHash,
    expiresAt
  ).run();

  return rawToken;
}

async function requireUser(request, env) {
  const rawToken =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (!rawToken) {
    return null;
  }

  const tokenHash =
    await sha256(rawToken);

  const session =
    await env.DB.prepare(`
      SELECT
        s.user_id,
        s.expires_at
      FROM sessions s
      WHERE s.token = ?
      LIMIT 1
    `).bind(
      tokenHash
    ).first();

  if (!session) {
    return null;
  }

  if (
    Number(session.expires_at) <=
    Date.now()
  ) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `).bind(
      tokenHash
    ).run();

    return null;
  }

  return getUserById(
    session.user_id,
    env
  );
}


/* ============================================================
   SIGNUP
   ============================================================ */

async function signup(request, env) {
  const body =
    await readJSON(request);

  if (!body) {
    return json({
      error: "Invalid JSON payload."
    }, 400);
  }

  const username =
    cleanUsername(body.username);

  const displayName =
    cleanText(
      body.displayName ??
      body.display_name ??
      "",
      80
    );

  const email =
    cleanEmail(body.email);

  const password =
    String(body.password || "");

  if (
    !/^[a-z0-9_]{3,30}$/.test(username)
  ) {
    return json({
      error:
        "Username must be 3-30 characters."
    }, 400);
  }

  if (displayName.length < 2) {
    return json({
      error:
        "Display name is required."
    }, 400);
  }

  if (
    !email ||
    !email.includes("@")
  ) {
    return json({
      error:
        "Enter a valid email."
    }, 400);
  }

  if (password.length < 8) {
    return json({
      error:
        "Password must contain at least 8 characters."
    }, 400);
  }

  const existing =
    await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE LOWER(username) = ?
         OR LOWER(email) = ?
      LIMIT 1
    `).bind(
      username,
      email
    ).first();

  if (existing) {
    return json({
      error:
        "Username or email is already registered."
    }, 409);
  }

  const passwordHash =
    await hashPassword(password);

  let result;

  try {
    result =
      await env.DB.prepare(`
        INSERT INTO users
        (
          username,
          display_name,
          email,
          password_hash,
          bio,
          skills,
          avatar_url,
          is_private
        )
        VALUES (?, ?, ?, ?, '', '', '', 0)
      `).bind(
        username,
        displayName,
        email,
        passwordHash
      ).run();

  } catch (error) {
    console.error(
      "Signup error:",
      error
    );

    return json({
      error:
        "Could not create account."
    }, 500);
  }

  const userId =
    Number(result.meta.last_row_id);

  const token =
    await createSession(
      userId,
      env
    );

  return withCookie(
    json({
      ok: true,
      user: {
        id: userId,
        username,
        displayName,
        email,
        bio: "",
        skills: [],
        avatarUrl: "",
        isPrivate: false
      }
    }, 201),
    makeSessionCookie(token)
  );
}


/* ============================================================
   LOGIN
   ============================================================ */

async function login(request, env) {
  const body =
    await readJSON(request);

  if (!body) {
    return json({
      error: "Invalid JSON payload."
    }, 400);
  }

  const loginValue =
    cleanText(
      body.login ??
      body.username ??
      body.email ??
      "",
      200
    ).toLowerCase();

  const password =
    String(body.password || "");

  if (
    !loginValue ||
    !password
  ) {
    return json({
      error:
        "Enter your username/email and password."
    }, 400);
  }

  const user =
    await env.DB.prepare(`
      SELECT *
      FROM users
      WHERE LOWER(username) = ?
         OR LOWER(email) = ?
      LIMIT 1
    `).bind(
      loginValue,
      loginValue
    ).first();

  if (!user) {
    return json({
      error:
        "Invalid login details."
    }, 401);
  }

  const valid =
    await verifyPassword(
      password,
      user.password_hash
    );

  if (!valid) {
    return json({
      error:
        "Invalid login details."
    }, 401);
  }

  const token =
    await createSession(
      Number(user.id),
      env
    );

  return withCookie(
    json({
      ok: true,
      user: publicUser(user)
    }),
    makeSessionCookie(token)
  );
}


/* ============================================================
   LOGOUT
   ============================================================ */

async function logout(request, env) {
  const rawToken =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (rawToken) {
    const tokenHash =
      await sha256(rawToken);

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `).bind(
      tokenHash
    ).run();
  }

  return withCookie(
    json({
      ok: true
    }),
    clearSessionCookie()
  );
}


/* ============================================================
   ME
   ============================================================ */

async function getMe(request, env) {
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      authenticated: false,
      user: null
    });
  }

  return json({
    authenticated: true,
    user: publicUser(user)
  });
}
// ============================================================
// PART 2 — PROFILES, SEARCH, FOLLOW, POSTS, LIKES,
// COMMENTS, SAVES, STORIES & REELS
// ============================================================

async function socialAPI(request, env, url, user) {
  const path = url.pathname;
  const method = request.method.toUpperCase();

  // PROFILE
  if (method === "GET" && path === "/api/profile") {
    return getMyProfile(user, env);
  }

  if (method === "PUT" && path === "/api/profile") {
    return updateProfile(request, env, user);
  }

  if (method === "PUT" && path === "/api/profile/update") {
    return updateProfile(request, env, user);
  }

  const profileMatch =
    path.match(/^\/api\/profile\/([^/]+)$/);

  if (method === "GET" && profileMatch) {
    return getPublicProfile(
      decodeURIComponent(profileMatch[1]),
      env,
      user
    );
  }

  // SEARCH
  if (method === "GET" && path === "/api/search") {
    return searchUsers(
      url.searchParams.get("q") || "",
      env
    );
  }

  // FOLLOW
  const followMatch =
    path.match(/^\/api\/users\/([^/]+)\/follow$/);

  if (method === "POST" && followMatch) {
    return followUser(
      decodeURIComponent(followMatch[1]),
      env,
      user
    );
  }

  if (method === "DELETE" && followMatch) {
    return unfollowUser(
      decodeURIComponent(followMatch[1]),
      env,
      user
    );
  }

  // FEED
  if (method === "GET" && path === "/api/feed") {
    return getFeed(env, user);
  }

  // POSTS
  if (method === "GET" && path === "/api/posts") {
    return getPosts(env, user, url);
  }

  if (method === "POST" && path === "/api/posts") {
    return createPost(request, env, user);
  }

  const postMatch =
    path.match(/^\/api\/posts\/([^/]+)$/);

  if (postMatch) {
    const postId =
      decodeURIComponent(postMatch[1]);

    if (method === "GET") {
      return getPost(postId, env, user);
    }

    if (method === "DELETE") {
      return deletePost(postId, env, user);
    }
  }

  // LIKE
  const likeMatch =
    path.match(/^\/api\/posts\/([^/]+)\/like$/);

  if (method === "POST" && likeMatch) {
    return likePost(
      decodeURIComponent(likeMatch[1]),
      env,
      user
    );
  }

  if (method === "DELETE" && likeMatch) {
    return unlikePost(
      decodeURIComponent(likeMatch[1]),
      env,
      user
    );
  }

  // COMMENTS
  const commentsMatch =
    path.match(/^\/api\/posts\/([^/]+)\/comments$/);

  if (method === "GET" && commentsMatch) {
    return getComments(
      decodeURIComponent(commentsMatch[1]),
      env
    );
  }

  if (method === "POST" && commentsMatch) {
    return createComment(
      request,
      env,
      user,
      decodeURIComponent(commentsMatch[1])
    );
  }

  // SAVE
  const saveMatch =
    path.match(/^\/api\/posts\/([^/]+)\/save$/);

  if (method === "POST" && saveMatch) {
    return savePost(
      decodeURIComponent(saveMatch[1]),
      env,
      user
    );
  }

  if (method === "DELETE" && saveMatch) {
    return unsavePost(
      decodeURIComponent(saveMatch[1]),
      env,
      user
    );
  }

  // SAVED
  if (method === "GET" && path === "/api/saved") {
    return getSavedPosts(env, user);
  }

  // STORIES
  if (method === "GET" && path === "/api/stories") {
    return getStories(env, user);
  }

  if (method === "POST" && path === "/api/stories") {
    return createStory(request, env, user);
  }

  // REELS
  if (method === "GET" && path === "/api/reels") {
    return getReels(env, user);
  }

  if (method === "POST" && path === "/api/reels") {
    return createReel(request, env, user);
  }

  return null;
}


// ============================================================
// PROFILE
// ============================================================

async function getMyProfile(user, env) {
  const profile =
    await env.DB.prepare(`
      SELECT *
      FROM users
      WHERE id = ?
      LIMIT 1
    `).bind(Number(user.id)).first();

  if (!profile) {
    return json({
      error: "User not found."
    }, 404);
  }

  const followers =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM follows
      WHERE following_id = ?
    `).bind(Number(user.id)).first();

  const following =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM follows
      WHERE follower_id = ?
    `).bind(Number(user.id)).first();

  const posts =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM posts
      WHERE user_id = ?
    `).bind(Number(user.id)).first();

  return json({
    user: publicUser(profile),
    stats: {
      followers: Number(followers?.count || 0),
      following: Number(following?.count || 0),
      posts: Number(posts?.count || 0)
    }
  });
}


async function updateProfile(request, env, user) {
  const body =
    await readJSON(request);

  if (!body) {
    return json({
      error: "Invalid JSON payload."
    }, 400);
  }

  const displayName =
    cleanText(
      body.displayName ??
      body.display_name ??
      user.display_name ??
      "",
      80
    );

  const bio =
    cleanText(
      body.bio ?? "",
      500
    );

  let skills =
    body.skills ?? [];

  if (typeof skills === "string") {
    try {
      skills = JSON.parse(skills);
    } catch {
      skills =
        skills
          .split(",")
          .map(x => x.trim())
          .filter(Boolean);
    }
  }

  if (!Array.isArray(skills)) {
    skills = [];
  }

  skills =
    skills
      .map(x => cleanText(x, 50))
      .filter(Boolean)
      .slice(0, 20);

  const avatarUrl =
    cleanText(
      body.avatarUrl ??
      body.avatar_url ??
      "",
      2000
    );

  await env.DB.prepare(`
    UPDATE users
    SET
      display_name = ?,
      bio = ?,
      skills = ?,
      avatar_url = ?
    WHERE id = ?
  `).bind(
    displayName,
    bio,
    JSON.stringify(skills),
    avatarUrl,
    Number(user.id)
  ).run();

  const updated =
    await getUserById(user.id, env);

  return json({
    ok: true,
    user: publicUser(updated)
  });
}


async function getPublicProfile(
  username,
  env,
  currentUser
) {
  const profile =
    await env.DB.prepare(`
      SELECT *
      FROM users
      WHERE LOWER(username) = ?
      LIMIT 1
    `).bind(
      String(username).toLowerCase()
    ).first();

  if (!profile) {
    return json({
      error: "User not found."
    }, 404);
  }

  const followers =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM follows
      WHERE following_id = ?
    `).bind(Number(profile.id)).first();

  const following =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM follows
      WHERE follower_id = ?
    `).bind(Number(profile.id)).first();

  const posts =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM posts
      WHERE user_id = ?
    `).bind(Number(profile.id)).first();

  const follow =
    await env.DB.prepare(`
      SELECT 1
      FROM follows
      WHERE follower_id = ?
        AND following_id = ?
      LIMIT 1
    `).bind(
      Number(currentUser.id),
      Number(profile.id)
    ).first();

  return json({
    user: publicUser(profile),
    following: !!follow,
    stats: {
      followers: Number(followers?.count || 0),
      following: Number(following?.count || 0),
      posts: Number(posts?.count || 0)
    }
  });
}


// ============================================================
// SEARCH
// ============================================================

async function searchUsers(query, env) {
  const q =
    cleanText(query, 100);

  if (!q) {
    return json({
      users: []
    });
  }

  const pattern =
    `%${q.toLowerCase()}%`;

  const result =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        display_name,
        email,
        bio,
        skills,
        avatar_url,
        is_private,
        created_at
      FROM users
      WHERE LOWER(username) LIKE ?
         OR LOWER(display_name) LIKE ?
      ORDER BY username
      LIMIT 30
    `).bind(
      pattern,
      pattern
    ).all();

  return json({
    users:
      (result.results || [])
        .map(publicUser)
  });
}


// ============================================================
// FOLLOW
// ============================================================

async function followUser(
  target,
  env,
  user
) {
  const targetUser =
    await findUser(target, env);

  if (!targetUser) {
    return json({
      error: "User not found."
    }, 404);
  }

  if (
    Number(targetUser.id) ===
    Number(user.id)
  ) {
    return json({
      error: "You cannot follow yourself."
    }, 400);
  }

  await env.DB.prepare(`
    INSERT OR IGNORE INTO follows
    (
      follower_id,
      following_id
    )
    VALUES (?, ?)
  `).bind(
    Number(user.id),
    Number(targetUser.id)
  ).run();

  await createNotification(
    env,
    String(targetUser.id),
    String(user.id),
    "follow",
    null
  );

  return json({
    ok: true,
    following: true
  });
}


async function unfollowUser(
  target,
  env,
  user
) {
  const targetUser =
    await findUser(target, env);

  if (!targetUser) {
    return json({
      error: "User not found."
    }, 404);
  }

  await env.DB.prepare(`
    DELETE FROM follows
    WHERE follower_id = ?
      AND following_id = ?
  `).bind(
    Number(user.id),
    Number(targetUser.id)
  ).run();

  return json({
    ok: true,
    following: false
  });
}


// ============================================================
// FEED
// ============================================================

async function getFeed(env, user) {
  const result =
    await env.DB.prepare(`
      SELECT
        p.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM posts p
      JOIN users u
        ON u.id = p.user_id
      WHERE p.user_id = ?
         OR p.user_id IN (
           SELECT following_id
           FROM follows
           WHERE follower_id = ?
         )
      ORDER BY p.created_at DESC
      LIMIT 100
    `).bind(
      Number(user.id),
      Number(user.id)
    ).all();

  return json({
    posts:
      await enrichPosts(
        result.results || [],
        env,
        user
      )
  });
}


// ============================================================
// POSTS
// ============================================================

async function getPosts(env, user, url) {
  const username =
    url.searchParams.get("username");

  let result;

  if (username) {
    result =
      await env.DB.prepare(`
        SELECT
          p.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM posts p
        JOIN users u
          ON u.id = p.user_id
        WHERE LOWER(u.username) = ?
        ORDER BY p.created_at DESC
        LIMIT 100
      `).bind(
        username.toLowerCase()
      ).all();
  } else {
    result =
      await env.DB.prepare(`
        SELECT
          p.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM posts p
        JOIN users u
          ON u.id = p.user_id
        ORDER BY p.created_at DESC
        LIMIT 100
      `).all();
  }

  return json({
    posts:
      await enrichPosts(
        result.results || [],
        env,
        user
      )
  });
}


async function createPost(
  request,
  env,
  user
) {
  const body =
    await readJSON(request);

  if (!body) {
    return json({
      error: "Invalid JSON payload."
    }, 400);
  }

  const caption =
    cleanText(
      body.caption ?? "",
      2200
    );

  const mediaUrl =
    cleanText(
      body.mediaUrl ??
      body.media_url ??
      "",
      2000
    );

  const mediaType =
    cleanText(
      body.mediaType ??
      body.media_type ??
      "image",
      30
    );

  if (!caption && !mediaUrl) {
    return json({
      error:
        "A post needs text or media."
    }, 400);
  }

  const postId =
    crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO posts
    (
      id,
      user_id,
      caption,
      media_url,
      media_type,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    postId,
    String(user.id),
    caption,
    mediaUrl,
    mediaType,
    now()
  ).run();

  const post =
    await env.DB.prepare(`
      SELECT
        p.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM posts p
      JOIN users u
        ON u.id = p.user_id
      WHERE p.id = ?
      LIMIT 1
    `).bind(postId).first();

  return json({
    ok: true,
    post:
      await enrichPost(
        post,
        env,
        user
      )
  }, 201);
}


async function getPost(
  postId,
  env,
  user
) {
  const post =
    await env.DB.prepare(`
      SELECT
        p.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM posts p
      JOIN users u
        ON u.id = p.user_id
      WHERE p.id = ?
      LIMIT 1
    `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  return json({
    post:
      await enrichPost(
        post,
        env,
        user
      )
  });
}


async function deletePost(
  postId,
  env,
  user
) {
  const post =
    await env.DB.prepare(`
      SELECT *
      FROM posts
      WHERE id = ?
      LIMIT 1
    `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  if (
    String(post.user_id) !==
    String(user.id)
  ) {
    return json({
      error:
        "You can only delete your own posts."
    }, 403);
  }

  await env.DB.batch([
    env.DB.prepare(`
      DELETE FROM likes
      WHERE post_id = ?
    `).bind(postId),

    env.DB.prepare(`
      DELETE FROM comments
      WHERE post_id = ?
    `).bind(postId),

    env.DB.prepare(`
      DELETE FROM saved_posts
      WHERE CAST(post_id AS TEXT) = ?
    `).bind(String(postId)),

    env.DB.prepare(`
      DELETE FROM posts
      WHERE id = ?
    `).bind(postId)
  ]);

  return json({
    ok: true
  });
}


// ============================================================
// LIKES
// ============================================================

async function likePost(
  postId,
  env,
  user
) {
  const post =
    await env.DB.prepare(`
      SELECT id, user_id
      FROM posts
      WHERE id = ?
      LIMIT 1
    `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  await env.DB.prepare(`
    INSERT OR IGNORE INTO likes
    (
      post_id,
      user_id
    )
    VALUES (?, ?)
  `).bind(
    postId,
    String(user.id)
  ).run();

  if (
    Number(post.user_id) !==
    Number(user.id)
  ) {
    await createNotification(
      env,
      String(post.user_id),
      String(user.id),
      "like",
      String(postId)
    );
  }

  return json({
    ok: true,
    liked: true
  });
}


async function unlikePost(
  postId,
  env,
  user
) {
  await env.DB.prepare(`
    DELETE FROM likes
    WHERE post_id = ?
      AND user_id = ?
  `).bind(
    postId,
    String(user.id)
  ).run();

  return json({
    ok: true,
    liked: false
  });
}


// ============================================================
// COMMENTS
// ============================================================

async function getComments(postId, env) {
  const result =
    await env.DB.prepare(`
      SELECT
        c.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM comments c
      JOIN users u
        ON u.id = c.user_id
      WHERE c.post_id = ?
      ORDER BY c.created_at ASC
      LIMIT 200
    `).bind(postId).all();

  return json({
    comments:
      result.results || []
  });
}


async function createComment(
  request,
  env,
  user,
  postId
) {
  const body =
    await readJSON(request);

  const content =
    cleanText(
      body?.content ??
      body?.text ??
      "",
      1000
    );

  if (!content) {
    return json({
      error:
        "Comment cannot be empty."
    }, 400);
  }

  const post =
    await env.DB.prepare(`
      SELECT id, user_id
      FROM posts
      WHERE id = ?
      LIMIT 1
    `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  const commentId =
    crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO comments
    (
      id,
      post_id,
      user_id,
      content,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    commentId,
    postId,
    String(user.id),
    content,
    now()
  ).run();

  if (
    Number(post.user_id) !==
    Number(user.id)
  ) {
    await createNotification(
      env,
      String(post.user_id),
      String(user.id),
      "comment",
      String(postId)
    );
  }

  return json({
    ok: true,
    commentId
  }, 201);
}


// ============================================================
// SAVED POSTS
// ============================================================

async function savePost(
  postId,
  env,
  user
) {
  await env.DB.prepare(`
    INSERT OR IGNORE INTO saved_posts
    (
      post_id,
      user_id
    )
    VALUES (?, ?)
  `).bind(
    String(postId),
    String(user.id)
  ).run();

  return json({
    ok: true,
    saved: true
  });
}


async function unsavePost(
  postId,
  env,
  user
) {
  await env.DB.prepare(`
    DELETE FROM saved_posts
    WHERE CAST(post_id AS TEXT) = ?
      AND CAST(user_id AS TEXT) = ?
  `).bind(
    String(postId),
    String(user.id)
  ).run();

  return json({
    ok: true,
    saved: false
  });
}


async function getSavedPosts(env, user) {
  const result =
    await env.DB.prepare(`
      SELECT
        p.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM saved_posts s
      JOIN posts p
        ON CAST(p.id AS TEXT) =
           CAST(s.post_id AS TEXT)
      JOIN users u
        ON u.id = p.user_id
      WHERE CAST(s.user_id AS TEXT) = ?
      ORDER BY p.created_at DESC
      LIMIT 100
    `).bind(
      String(user.id)
    ).all();

  return json({
    posts:
      await enrichPosts(
        result.results || [],
        env,
        user
      )
  });
}


// ============================================================
// STORIES
// ============================================================

async function getStories(env, user) {
  const result =
    await env.DB.prepare(`
      SELECT
        s.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM stories s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.expires_at > ?
      ORDER BY s.created_at DESC
      LIMIT 100
    `).bind(
      Date.now()
    ).all();

  return json({
    stories:
      result.results || []
  });
}


async function createStory(
  request,
  env,
  user
) {
  const body =
    await readJSON(request);

  const content =
    cleanText(
      body?.content ?? "",
      1000
    );

  const mediaUrl =
    cleanText(
      body?.mediaUrl ??
      body?.media_url ??
      "",
      2000
    );

  const mediaType =
    cleanText(
      body?.mediaType ??
      body?.media_type ??
      "image",
      30
    );

  if (!content && !mediaUrl) {
    return json({
      error:
        "Story needs content or media."
    }, 400);
  }

  const storyId =
    crypto.randomUUID();

  const expiresAt =
    Date.now() +
    24 * 60 * 60 * 1000;

  await env.DB.prepare(`
    INSERT INTO stories
    (
      id,
      user_id,
      content,
      media_url,
      media_type,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    storyId,
    String(user.id),
    content,
    mediaUrl,
    mediaType,
    now(),
    expiresAt
  ).run();

  return json({
    ok: true,
    storyId
  }, 201);
}


// ============================================================
// REELS
// ============================================================

async function getReels(env, user) {
  const result =
    await env.DB.prepare(`
      SELECT
        r.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM reels r
      JOIN users u
        ON u.id = r.user_id
      ORDER BY r.created_at DESC
      LIMIT 100
    `).all();

  return json({
    reels:
      result.results || []
  });
}


async function createReel(
  request,
  env,
  user
) {
  const body =
    await readJSON(request);

  const mediaUrl =
    cleanText(
      body?.mediaUrl ??
      body?.media_url ??
      "",
      2000
    );

  const caption =
    cleanText(
      body?.caption ?? "",
      2200
    );

  if (!mediaUrl) {
    return json({
      error:
        "Reel media is required."
    }, 400);
  }

  const reelId =
    crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO reels
    (
      id,
      user_id,
      media_url,
      caption,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    reelId,
    String(user.id),
    mediaUrl,
    caption,
    now()
  ).run();

  return json({
    ok: true,
    reelId
  }, 201);
}


// ============================================================
// POST HELPERS
// ============================================================

async function enrichPosts(
  posts,
  env,
  user
) {
  const output = [];

  for (const post of posts) {
    output.push(
      await enrichPost(
        post,
        env,
        user
      )
    );
  }

  return output;
}


async function enrichPost(
  post,
  env,
  user
) {
  if (!post) {
    return null;
  }

  const likes =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM likes
      WHERE post_id = ?
    `).bind(
      String(post.id)
    ).first();

  const comments =
    await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM comments
      WHERE post_id = ?
    `).bind(
      String(post.id)
    ).first();

  const liked =
    await env.DB.prepare(`
      SELECT 1
      FROM likes
      WHERE post_id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      String(post.id),
      String(user.id)
    ).first();

  const saved =
    await env.DB.prepare(`
      SELECT 1
      FROM saved_posts
      WHERE CAST(post_id AS TEXT) = ?
        AND CAST(user_id AS TEXT) = ?
      LIMIT 1
    `).bind(
      String(post.id),
      String(user.id)
    ).first();

  return {
    id: post.id,
    userId: post.user_id,
    username: post.username,
    displayName:
      post.display_name || "",
    avatarUrl:
      post.avatar_url || "",
    caption:
      post.caption || "",
    mediaUrl:
      post.media_url || "",
    mediaType:
      post.media_type || "",
    createdAt:
      post.created_at,
    likes:
      Number(likes?.count || 0),
    comments:
      Number(comments?.count || 0),
    liked: !!liked,
    saved: !!saved
  };
}


async function findUser(value, env) {
  const clean =
    String(value || "")
      .trim()
      .toLowerCase();

  if (!clean) {
    return null;
  }

  if (/^\d+$/.test(clean)) {
    return env.DB.prepare(`
      SELECT *
      FROM users
      WHERE id = ?
      LIMIT 1
    `).bind(
      Number(clean)
    ).first();
  }

  return env.DB.prepare(`
    SELECT *
    FROM users
    WHERE LOWER(username) = ?
       OR LOWER(email) = ?
    LIMIT 1
  `).bind(
    clean,
    clean
  ).first();
}


async function createNotification(
  env,
  recipientId,
  actorId,
  type,
  postId = null
) {
  try {
    await env.DB.prepare(`
      INSERT INTO notifications
      (
        id,
        user_id,
        actor_id,
        type,
        post_id,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      String(recipientId),
      String(actorId),
      type,
      postId,
      now()
    ).run();
  } catch (error) {
    console.error(
      "Notification error:",
      error
    );
  }
}
// ============================================================
// PART 3 — CHAT, SETTINGS, NOTIFICATIONS, PASSWORD RESET
//         + MAIN CLOUDFLARE WORKER
// ============================================================


// ============================================================
// SETTINGS
// ============================================================

async function ensureSettings(userId, env) {
  await env.DB.prepare(`
    INSERT OR IGNORE INTO user_settings
    (
      user_id,
      theme,
      profile_visibility,
      message_privacy,
      notification_settings
    )
    VALUES (?, 'system', 'public', 'everyone', '{}')
  `).bind(
    String(userId)
  ).run();
}


async function settingsAPI(
  request,
  env,
  url,
  user
) {
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (
    method === "GET" &&
    path === "/api/settings"
  ) {
    await ensureSettings(
      user.id,
      env
    );

    const settings =
      await env.DB.prepare(`
        SELECT *
        FROM user_settings
        WHERE user_id = ?
        LIMIT 1
      `).bind(
        String(user.id)
      ).first();

    return json({
      settings: settings || {
        user_id: String(user.id),
        theme: "system",
        profile_visibility: "public",
        message_privacy: "everyone",
        notification_settings: "{}"
      }
    });
  }


  if (
    method === "PUT" &&
    path === "/api/settings"
  ) {
    const body =
      await readJSON(request);

    await ensureSettings(
      user.id,
      env
    );

    const theme =
      ["system", "light", "dark"]
        .includes(body?.theme)
        ? body.theme
        : "system";

    const profileVisibility =
      ["public", "private"]
        .includes(
          body?.profileVisibility
        )
        ? body.profileVisibility
        : "public";

    const messagePrivacy =
      ["everyone", "followers", "nobody"]
        .includes(
          body?.messagePrivacy
        )
        ? body.messagePrivacy
        : "everyone";

    const notificationSettings =
      typeof body?.notificationSettings ===
      "object"
        ? JSON.stringify(
            body.notificationSettings
          )
        : "{}";

    await env.DB.prepare(`
      UPDATE user_settings
      SET
        theme = ?,
        profile_visibility = ?,
        message_privacy = ?,
        notification_settings = ?
      WHERE user_id = ?
    `).bind(
      theme,
      profileVisibility,
      messagePrivacy,
      notificationSettings,
      String(user.id)
    ).run();

    return json({
      ok: true
    });
  }


  if (
    (
      method === "POST" ||
      method === "PUT"
    ) &&
    path === "/api/settings/password"
  ) {
    const body =
      await readJSON(request);

    const currentPassword =
      String(
        body?.currentPassword ||
        body?.current_password ||
        ""
      );

    const newPassword =
      String(
        body?.newPassword ||
        body?.new_password ||
        body?.password ||
        ""
      );

    if (
      !currentPassword ||
      newPassword.length < 8
    ) {
      return json({
        error:
          "Enter your current password and a new password of at least 8 characters."
      }, 400);
    }

    const valid =
      await verifyPassword(
        currentPassword,
        user.password_hash
      );

    if (!valid) {
      return json({
        error:
          "Current password is incorrect."
      }, 401);
    }

    const passwordHash =
      await hashPassword(
        newPassword
      );

    await env.DB.prepare(`
      UPDATE users
      SET password_hash = ?
      WHERE id = ?
    `).bind(
      passwordHash,
      Number(user.id)
    ).run();

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
    `).bind(
      Number(user.id)
    ).run();

    const token =
      await createSession(
        Number(user.id),
        env
      );

    return withCookie(
      json({
        ok: true
      }),
      makeSessionCookie(token)
    );
  }

  return null;
}


// ============================================================
// CHAT
// ============================================================

async function chatAPI(
  request,
  env,
  url,
  user
) {
  const path = url.pathname;
  const method = request.method.toUpperCase();


  if (
    method === "GET" &&
    path === "/api/chats"
  ) {
    return getChats(
      env,
      user
    );
  }


  if (
    method === "POST" &&
    path === "/api/chats"
  ) {
    return createChat(
      request,
      env,
      user
    );
  }


  if (
    method === "POST" &&
    path === "/api/groups"
  ) {
    return createGroup(
      request,
      env,
      user
    );
  }


  const chatMatch =
    path.match(
      /^\/api\/chats\/([^/]+)$/
    );

  if (
    method === "GET" &&
    chatMatch
  ) {
    return getChat(
      decodeURIComponent(
        chatMatch[1]
      ),
      env,
      user
    );
  }


  const messageMatch =
    path.match(
      /^\/api\/chats\/([^/]+)\/messages$/
    );

  if (messageMatch) {
    const chatId =
      decodeURIComponent(
        messageMatch[1]
      );

    if (method === "GET") {
      return getMessages(
        chatId,
        env,
        user
      );
    }

    if (method === "POST") {
      return sendMessage(
        request,
        chatId,
        env,
        user
      );
    }
  }

  return null;
}


async function getChats(env, user) {
  const result =
    await env.DB.prepare(`
      SELECT
        c.*,
        (
          SELECT m.content
          FROM messages m
          WHERE m.chat_id = c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message,
        (
          SELECT m.created_at
          FROM messages m
          WHERE m.chat_id = c.id
          ORDER BY m.created_at DESC
          LIMIT 1
        ) AS last_message_at
      FROM chats c
      JOIN chat_members cm
        ON cm.chat_id = c.id
      WHERE cm.user_id = ?
      ORDER BY
        COALESCE(
          last_message_at,
          c.created_at
        ) DESC
    `).bind(
      String(user.id)
    ).all();

  return json({
    chats:
      result.results || []
  });
}


async function getChat(
  chatId,
  env,
  user
) {
  const member =
    await env.DB.prepare(`
      SELECT 1
      FROM chat_members
      WHERE chat_id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      chatId,
      String(user.id)
    ).first();

  if (!member) {
    return json({
      error: "Chat not found."
    }, 404);
  }

  const chat =
    await env.DB.prepare(`
      SELECT *
      FROM chats
      WHERE id = ?
      LIMIT 1
    `).bind(
      chatId
    ).first();

  const members =
    await env.DB.prepare(`
      SELECT
        u.id,
        u.username,
        u.display_name,
        u.avatar_url
      FROM chat_members cm
      JOIN users u
        ON u.id = cm.user_id
      WHERE cm.chat_id = ?
    `).bind(
      chatId
    ).all();

  return json({
    chat,
    members:
      members.results || []
  });
}


async function createChat(
  request,
  env,
  user
) {
  const body =
    await readJSON(request);

  const target =
    body?.userId ??
    body?.user_id ??
    body?.username ??
    body?.email;

  const targetUser =
    await findUser(
      target,
      env
    );

  if (!targetUser) {
    return json({
      error: "User not found."
    }, 404);
  }

  if (
    Number(targetUser.id) ===
    Number(user.id)
  ) {
    return json({
      error:
        "You cannot chat with yourself."
    }, 400);
  }

  const existing =
    await env.DB.prepare(`
      SELECT c.id
      FROM chats c
      JOIN chat_members a
        ON a.chat_id = c.id
      JOIN chat_members b
        ON b.chat_id = c.id
      WHERE a.user_id = ?
        AND b.user_id = ?
        AND c.is_group = 0
      LIMIT 1
    `).bind(
      String(user.id),
      String(targetUser.id)
    ).first();

  if (existing) {
    return json({
      ok: true,
      chatId: existing.id
    });
  }

  const chatId =
    crypto.randomUUID();

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO chats
      (
        id,
        name,
        is_group,
        created_at
      )
      VALUES (?, '', 0, ?)
    `).bind(
      chatId,
      now()
    ),

    env.DB.prepare(`
      INSERT INTO chat_members
      (
        chat_id,
        user_id
      )
      VALUES (?, ?)
    `).bind(
      chatId,
      String(user.id)
    ),

    env.DB.prepare(`
      INSERT INTO chat_members
      (
        chat_id,
        user_id
      )
      VALUES (?, ?)
    `).bind(
      chatId,
      String(targetUser.id)
    )
  ]);

  return json({
    ok: true,
    chatId
  }, 201);
}


async function createGroup(
  request,
  env,
  user
) {
  const body =
    await readJSON(request);

  const name =
    cleanText(
      body?.name,
      80
    );

  if (!name) {
    return json({
      error:
        "Group name is required."
    }, 400);
  }

  let members =
    body?.memberIds ||
    body?.member_ids ||
    [];

  if (!Array.isArray(members)) {
    members = [];
  }

  members =
    members
      .map(x => String(x))
      .filter(Boolean);

  members.push(
    String(user.id)
  );

  members =
    [...new Set(members)];

  const chatId =
    crypto.randomUUID();

  const statements = [
    env.DB.prepare(`
      INSERT INTO chats
      (
        id,
        name,
        is_group,
        created_at
      )
      VALUES (?, ?, 1, ?)
    `).bind(
      chatId,
      name,
      now()
    )
  ];

  for (const member of members) {
    statements.push(
      env.DB.prepare(`
        INSERT OR IGNORE INTO chat_members
        (
          chat_id,
          user_id
        )
        VALUES (?, ?)
      `).bind(
        chatId,
        member
      )
    );
  }

  await env.DB.batch(
    statements
  );

  return json({
    ok: true,
    chatId
  }, 201);
}


async function getMessages(
  chatId,
  env,
  user
) {
  const member =
    await env.DB.prepare(`
      SELECT 1
      FROM chat_members
      WHERE chat_id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      chatId,
      String(user.id)
    ).first();

  if (!member) {
    return json({
      error: "Chat not found."
    }, 404);
  }

  const result =
    await env.DB.prepare(`
      SELECT
        m.*,
        u.username,
        u.display_name,
        u.avatar_url
      FROM messages m
      JOIN users u
        ON u.id = m.sender_id
      WHERE m.chat_id = ?
      ORDER BY m.created_at ASC
      LIMIT 500
    `).bind(
      chatId
    ).all();

  return json({
    messages:
      result.results || []
  });
}


async function sendMessage(
  request,
  chatId,
  env,
  user
) {
  const member =
    await env.DB.prepare(`
      SELECT 1
      FROM chat_members
      WHERE chat_id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      chatId,
      String(user.id)
    ).first();

  if (!member) {
    return json({
      error: "Chat not found."
    }, 404);
  }

  const body =
    await readJSON(request);

  const content =
    cleanText(
      body?.content ??
      body?.text ??
      "",
      5000
    );

  const mediaUrl =
    cleanText(
      body?.mediaUrl ??
      body?.media_url ??
      "",
      2000
    );

  if (!content && !mediaUrl) {
    return json({
      error:
        "Message cannot be empty."
    }, 400);
  }

  const messageId =
    crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO messages
    (
      id,
      chat_id,
      sender_id,
      content,
      media_url,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    messageId,
    chatId,
    String(user.id),
    content,
    mediaUrl,
    now()
  ).run();

  return json({
    ok: true,
    message: {
      id: messageId,
      chatId,
      senderId: user.id,
      content,
      mediaUrl,
      createdAt: now()
    }
  }, 201);
}


// ============================================================
// NOTIFICATIONS
// ============================================================

async function notificationsAPI(
  request,
  env,
  url,
  user
) {
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (
    method === "GET" &&
    path === "/api/notifications"
  ) {
    const result =
      await env.DB.prepare(`
        SELECT
          n.*,
          u.username,
          u.display_name,
          u.avatar_url
        FROM notifications n
        LEFT JOIN users u
          ON u.id = n.actor_id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC
        LIMIT 100
      `).bind(
        String(user.id)
      ).all();

    return json({
      notifications:
        result.results || []
    });
  }

  if (
    method === "POST" &&
    path === "/api/notifications/read"
  ) {
    await env.DB.prepare(`
      UPDATE notifications
      SET is_read = 1
      WHERE user_id = ?
    `).bind(
      String(user.id)
    ).run();

    return json({
      ok: true
    });
  }

  return null;
}


// ============================================================
// PASSWORD RESET
// ============================================================

async function forgotPassword(
  request,
  env
) {
  const body =
    await readJSON(request);

  const email =
    cleanEmail(
      body?.email
    );

  if (!email) {
    return json({
      error:
        "Email is required."
    }, 400);
  }

  const user =
    await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE LOWER(email) = ?
      LIMIT 1
    `).bind(
      email
    ).first();

  // Always return the same response.
  // This prevents revealing whether an account exists.
  if (!user) {
    return json({
      ok: true,
      message:
        "If an account exists, reset instructions will be sent."
    });
  }

  const rawToken =
    randomToken(32);

  const tokenHash =
    await sha256(rawToken);

  const expiresAt =
    Date.now() +
    15 * 60 * 1000;

  await env.DB.prepare(`
    DELETE FROM password_resets
    WHERE user_id = ?
  `).bind(
    String(user.id)
  ).run();

  await env.DB.prepare(`
    INSERT INTO password_resets
    (
      id,
      user_id,
      token_hash,
      expires_at,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    String(user.id),
    tokenHash,
    expiresAt,
    now()
  ).run();

  // No email provider is required for the account system itself.
  // Your frontend can later connect this to an email service.

  console.log(
    "Password reset token created for user:",
    user.id
  );

  return json({
    ok: true,
    message:
      "If an account exists, reset instructions will be sent."
  });
}


async function resetPassword(
  request,
  env
) {
  const body =
    await readJSON(request);

  const token =
    String(
      body?.token ||
      body?.resetToken ||
      ""
    );

  const newPassword =
    String(
      body?.password ||
      body?.newPassword ||
      body?.new_password ||
      ""
    );

  if (
    !token ||
    newPassword.length < 8
  ) {
    return json({
      error:
        "Invalid reset request."
    }, 400);
  }

  const tokenHash =
    await sha256(token);

  const reset =
    await env.DB.prepare(`
      SELECT *
      FROM password_resets
      WHERE token_hash = ?
        AND expires_at > ?
      LIMIT 1
    `).bind(
      tokenHash,
      Date.now()
    ).first();

  if (!reset) {
    return json({
      error:
        "Reset token is invalid or expired."
    }, 400);
  }

  const passwordHash =
    await hashPassword(
      newPassword
    );

  await env.DB.batch([
    env.DB.prepare(`
      UPDATE users
      SET password_hash = ?
      WHERE id = ?
    `).bind(
      passwordHash,
      Number(reset.user_id)
    ),

    env.DB.prepare(`
      DELETE FROM sessions
      WHERE user_id = ?
    `).bind(
      Number(reset.user_id)
    ),

    env.DB.prepare(`
      DELETE FROM password_resets
      WHERE user_id = ?
    `).bind(
      String(reset.user_id)
    )
  ]);

  return json({
    ok: true,
    message:
      "Password has been reset."
  });
}


// ============================================================
// MAIN API ROUTER
// ============================================================

async function api(
  request,
  env,
  url
) {
  const path =
    url.pathname;

  const method =
    request.method.toUpperCase();


  // PUBLIC AUTH
  if (
    method === "POST" &&
    path === "/api/signup"
  ) {
    return signup(
      request,
      env
    );
  }

  if (
    method === "POST" &&
    path === "/api/login"
  ) {
    return login(
      request,
      env
    );
  }

  if (
    method === "POST" &&
    path === "/api/logout"
  ) {
    return logout(
      request,
      env
    );
  }

  if (
    method === "GET" &&
    path === "/api/me"
  ) {
    return getMe(
      request,
      env
    );
  }

  if (
    method === "POST" &&
    path === "/api/forgot-password"
  ) {
    return forgotPassword(
      request,
      env
    );
  }

  if (
    method === "POST" &&
    path === "/api/reset-password"
  ) {
    return resetPassword(
      request,
      env
    );
  }


  // EVERYTHING BELOW REQUIRES LOGIN
  const user =
    await requireUser(
      request,
      env
    );

  if (!user) {
    return json({
      error:
        "Session expired. Please log in again."
    }, 401);
  }


  // SOCIAL
  const social =
    await socialAPI(
      request,
      env,
      url,
      user
    );

  if (social) {
    return social;
  }


  // CHAT
  const chat =
    await chatAPI(
      request,
      env,
      url,
      user
    );

  if (chat) {
    return chat;
  }


  // SETTINGS
  const settings =
    await settingsAPI(
      request,
      env,
      url,
      user
    );

  if (settings) {
    return settings;
  }


  // NOTIFICATIONS
  const notifications =
    await notificationsAPI(
      request,
      env,
      url,
      user
    );

  if (notifications) {
    return notifications;
  }


  return json({
    error:
      "API route not found."
  }, 404);
}


// ============================================================
// CLOUDFLARE WORKER ENTRY
// ============================================================

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    try {

      // API
      if (
        url.pathname.startsWith(
          "/api/"
        )
      ) {
        return await api(
          request,
          env,
          url
        );
      }


      // MEDIA
      if (
        url.pathname.startsWith(
          "/media/"
        )
      ) {
        if (!env.MEDIA) {
          return new Response(
            "Media storage is not configured.",
            {
              status: 503
            }
          );
        }

        const key =
          decodeURIComponent(
            url.pathname.slice(
              "/media/".length
            )
          );

        const object =
          await env.MEDIA.get(key);

        if (!object) {
          return new Response(
            "Not found",
            {
              status: 404
            }
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
            status: 200,
            headers
          }
        );
      }


      // WEBSITE
      if (env.ASSETS) {
        return env.ASSETS.fetch(
          request
        );
      }

      return new Response(
        "Zilnet is running.",
        {
          status: 200,
          headers: {
            "Content-Type":
              "text/plain; charset=utf-8"
          }
        }
      );

    } catch (error) {

      console.error(
        "Worker error:",
        error
      );

      return json({
        error:
          "Internal server error."
      }, 500);
    }
  }
};
