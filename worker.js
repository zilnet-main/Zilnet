// ============================================================
// ZILNET BACKEND
// Cloudflare Worker + D1
// ============================================================

const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 150000;
const SESSION_COOKIE = "zilnet_session";

// ------------------------------------------------------------
// MAIN
// ------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // API
      if (url.pathname.startsWith("/api/")) {
        return await api(request, env, url);
      }

      // R2 media (optional – only works if MEDIA binding exists)
      if (url.pathname.startsWith("/media/")) {
        return await serveMedia(request, env, url);
      }

      // Everything else = index.html/static assets
      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error(error);

      return json({
        error: "Internal server error"
      }, 500);
    }
  }
};


// ============================================================
// API ROUTER
// ============================================================

async function api(request, env, url) {
  const path = url.pathname;
  const method = request.method.toUpperCase();

  // ---------- PUBLIC AUTH ----------

  if (method === "POST" && path === "/api/signup") {
    return signup(request, env);
  }

  if (method === "POST" && path === "/api/login") {
    return login(request, env);
  }

  if (method === "POST" && path === "/api/logout") {
    return logout(request, env);
  }

  if (method === "GET" && path === "/api/me") {
    return getMe(request, env);
  }

  if (method === "POST" && path === "/api/forgot-password") {
    return forgotPassword(request, env);
  }

  if (method === "POST" && path === "/api/reset-password") {
    return resetPassword(request, env);
  }


  // ---------- AUTH REQUIRED ----------

  const user = await requireUser(request, env);

  if (!user) {
    return json({
      error: "Authentication required"
    }, 401);
  }


  // ---------- PROFILE ----------

  if (method === "GET" && path === "/api/profile") {
    return getProfile(user, env);
  }

  if (method === "PUT" && path === "/api/profile/update") {
    return updateProfile(request, user, env);
  }

  if (method === "GET" && path.startsWith("/api/profile/")) {
    const username = decodeURIComponent(
      path.substring("/api/profile/".length)
    );

    return getPublicProfile(username, user, env);
  }


  // ---------- SEARCH ----------

  if (method === "GET" && path === "/api/search") {
    return searchUsers(url, user, env);
  }


  // ---------- FOLLOW ----------

  if (
    method === "POST" &&
    /^\/api\/users\/[^/]+\/follow$/.test(path)
  ) {
    const id = path.split("/")[3];

    return toggleFollow(id, user, env);
  }


  // ---------- FEED ----------

  if (method === "GET" && path === "/api/feed") {
    return getFeed(user, env);
  }


  // ---------- POSTS ----------

  if (method === "POST" && path === "/api/posts") {
    return createPost(request, user, env);
  }

  if (
    method === "DELETE" &&
    /^\/api\/posts\/[^/]+$/.test(path)
  ) {
    const id = path.split("/")[3];

    return deletePost(id, user, env);
  }

  if (
    method === "POST" &&
    /^\/api\/posts\/[^/]+\/like$/.test(path)
  ) {
    const id = path.split("/")[3];

    return toggleLike(id, user, env);
  }

  if (
    method === "GET" &&
    /^\/api\/posts\/[^/]+\/comments$/.test(path)
  ) {
    const id = path.split("/")[3];

    return getComments(id, env);
  }

  if (
    method === "POST" &&
    /^\/api\/posts\/[^/]+\/comments$/.test(path)
  ) {
    const id = path.split("/")[3];

    return createComment(id, request, user, env);
  }

  if (
    method === "POST" &&
    /^\/api\/posts\/[^/]+\/save$/.test(path)
  ) {
    const id = path.split("/")[3];

    return toggleSave(id, user, env);
  }


  // ---------- UPLOAD ----------

  if (method === "POST" && path === "/api/upload") {
    return uploadMedia(request, user, env);
  }


  // ---------- STORIES ----------

  if (method === "GET" && path === "/api/stories/feed") {
    return getStoryFeed(user, env);
  }

  if (method === "POST" && path === "/api/stories") {
    return createStory(request, user, env);
  }


  // ---------- REELS ----------

  if (method === "GET" && path === "/api/reels/feed") {
    return getReels(user, env);
  }

  if (method === "POST" && path === "/api/reels") {
    return createReel(request, user, env);
  }


  // ---------- CHAT ----------

  if (method === "GET" && path === "/api/chats") {
    return getChats(user, env);
  }

  if (method === "POST" && path === "/api/chats") {
    return createChat(request, user, env);
  }

  if (
    method === "GET" &&
    /^\/api\/chats\/[^/]+\/messages$/.test(path)
  ) {
    const chatId = path.split("/")[3];

    return getMessages(chatId, user, env);
  }

  if (
    method === "POST" &&
    /^\/api\/chats\/[^/]+\/messages$/.test(path)
  ) {
    const chatId = path.split("/")[3];

    return sendMessage(chatId, request, user, env);
  }


  // ---------- GROUPS ----------

  if (method === "POST" && path === "/api/groups") {
    return createGroup(request, user, env);
  }


  // ---------- NOTIFICATIONS ----------

  if (method === "GET" && path === "/api/notifications") {
    return getNotifications(user, env);
  }

  if (method === "POST" && path === "/api/notifications/read") {
    return markNotificationsRead(user, env);
  }


  // ---------- SETTINGS ----------

  if (method === "GET" && path === "/api/settings") {
    return getSettings(user, env);
  }

  if (method === "PUT" && path === "/api/settings") {
    return updateSettings(request, user, env);
  }


  return json({
    error: "API route not found"
  }, 404);
}


// ============================================================
// AUTH
// ============================================================

async function signup(request, env) {
  const body = await readJSON(request);

  const username = cleanUsername(body.username);
  const displayName = cleanText(body.displayName, 80);
  const email = cleanEmail(body.email);
  const password = String(body.password || "");

  if (!username || !/^[a-z0-9_]{3,30}$/.test(username)) {
    return json({
      error: "Username must be 3-30 characters and use letters, numbers or _."
    }, 400);
  }

  if (!displayName || displayName.length < 2) {
    return json({
      error: "Display name is required."
    }, 400);
  }

  if (!email || !email.includes("@")) {
    return json({
      error: "Enter a valid email."
    }, 400);
  }

  if (password.length < 8) {
    return json({
      error: "Password must contain at least 8 characters."
    }, 400);
  }

  const existing = await env.DB.prepare(`
    SELECT id
    FROM users
    WHERE username = ? OR email = ?
    LIMIT 1
  `).bind(username, email).first();

  if (existing) {
    return json({
      error: "Username or email is already registered."
    }, 409);
  }

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  await env.DB.prepare(`
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
    VALUES (?, ?, ?, ?, ?, '', '', '', ?)
  `).bind(
    id,
    username,
    displayName,
    email,
    passwordHash,
    now()
  ).run();

  const token = await createSession(id, env);

  return withCookie(
    json({
      ok: true,
      user: {
        id,
        username,
        displayName,
        email
      }
    }),
    makeSessionCookie(token)
  );
}


async function login(request, env) {
  const body = await readJSON(request);

  const loginValue = cleanText(body.login, 100).toLowerCase();
  const password = String(body.password || "");

  if (!loginValue || !password) {
    return json({
      error: "Enter your username/email and password."
    }, 400);
  }

  const user = await env.DB.prepare(`
    SELECT *
    FROM users
    WHERE LOWER(username) = ? OR LOWER(email) = ?
    LIMIT 1
  `).bind(loginValue, loginValue).first();

  if (!user) {
    return json({
      error: "Invalid login details."
    }, 401);
  }

  const valid = await verifyPassword(
    password,
    user.password_hash
  );

  if (!valid) {
    return json({
      error: "Invalid login details."
    }, 401);
  }

  const token = await createSession(user.id, env);

  return withCookie(
    json({
      ok: true,
      user: publicUser(user)
    }),
    makeSessionCookie(token)
  );
}


async function logout(request, env) {
  const token = getCookie(request, SESSION_COOKIE);

  if (token) {
    const hash = await sha256(token);

    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `).bind(hash).run();
  }

  return withCookie(
    json({ ok: true }),
    clearSessionCookie()
  );
}


async function getMe(request, env) {
  const user = await requireUser(request, env);

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
// PASSWORD RESET
// ============================================================

async function forgotPassword(request, env) {
  const body = await readJSON(request);

  const email = cleanEmail(body.email);

  if (!email) {
    return json({
      error: "Enter your email."
    }, 400);
  }

  const user = await env.DB.prepare(`
    SELECT id, email
    FROM users
    WHERE LOWER(email) = ?
    LIMIT 1
  `).bind(email).first();

  // Always return generic response.
  if (!user) {
    return json({
      ok: true,
      message: "If an account exists, a reset email will be sent."
    });
  }

  const rawToken = randomToken(48);
  const tokenHash = await sha256(rawToken);

  const expires = Date.now() + 30 * 60 * 1000;

  await env.DB.prepare(`
    DELETE FROM password_resets
    WHERE user_id = ?
  `).bind(user.id).run();

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
    user.id,
    tokenHash,
    expires,
    now()
  ).run();

  // Resend is optional but recommended.
  if (env.RESEND_API_KEY && env.RESET_FROM_EMAIL) {
    const resetURL =
      `${new URL(request.url).origin}/?reset=${encodeURIComponent(rawToken)}`;

    await sendResetEmail(
      env,
      user.email,
      resetURL
    );
  }

  return json({
    ok: true,
    message: "If an account exists, a reset email will be sent."
  });
}


async function resetPassword(request, env) {
  const body = await readJSON(request);

  const token = String(body.token || "");
  const newPassword = String(body.password || "");

  if (!token || newPassword.length < 8) {
    return json({
      error: "Invalid reset request."
    }, 400);
  }

  const tokenHash = await sha256(token);

  const reset = await env.DB.prepare(`
    SELECT *
    FROM password_resets
    WHERE token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!reset || Number(reset.expires_at) < Date.now()) {
    return json({
      error: "This reset link is invalid or expired."
    }, 400);
  }

  const passwordHash = await hashPassword(newPassword);

  await env.DB.prepare(`
    UPDATE users
    SET password_hash = ?
    WHERE id = ?
  `).bind(
    passwordHash,
    reset.user_id
  ).run();

  // Kill existing sessions.
  await env.DB.prepare(`
    DELETE FROM sessions
    WHERE user_id = ?
  `).bind(reset.user_id).run();

  await env.DB.prepare(`
    DELETE FROM password_resets
    WHERE user_id = ?
  `).bind(reset.user_id).run();

  return json({
    ok: true,
    message: "Password changed successfully."
  });
}


// ============================================================
// PROFILE
// ============================================================

async function getProfile(user, env) {
  return json({
    user: publicUser(user)
  });
}


async function getPublicProfile(username, currentUser, env) {
  const profile = await env.DB.prepare(`
    SELECT
      id,
      username,
      display_name,
      bio,
      skills,
      avatar_url,
      created_at
    FROM users
    WHERE LOWER(username) = ?
    LIMIT 1
  `).bind(username.toLowerCase()).first();

  if (!profile) {
    return json({
      error: "User not found."
    }, 404);
  }

  const followers = await count(
    env.DB,
    `SELECT COUNT(*) AS n FROM follows WHERE following_id = ?`,
    profile.id
  );

  const following = await count(
    env.DB,
    `SELECT COUNT(*) AS n FROM follows WHERE follower_id = ?`,
    profile.id
  );

  const isFollowing = await env.DB.prepare(`
    SELECT 1
    FROM follows
    WHERE follower_id = ? AND following_id = ?
    LIMIT 1
  `).bind(
    currentUser.id,
    profile.id
  ).first();

  return json({
    profile: {
      ...profile,
      skills: parseSkills(profile.skills),
      followers,
      following,
      isFollowing: !!isFollowing
    }
  });
}


async function updateProfile(request, user, env) {
  const body = await readJSON(request);

  const displayName =
    cleanText(body.displayName, 80) || user.display_name;

  const bio =
    cleanText(body.bio, 500);

  const skills =
    Array.isArray(body.skills)
      ? body.skills
          .map(x => cleanText(x, 40))
          .filter(Boolean)
          .slice(0, 20)
      : parseSkills(user.skills);

  let avatarUrl = user.avatar_url || "";

  if (body.avatarUrl) {
    avatarUrl = cleanText(body.avatarUrl, 500);
  }

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
    user.id
  ).run();

  const updated = await getUserById(user.id, env);

  return json({
    ok: true,
    user: publicUser(updated)
  });
}


// ============================================================
// SEARCH
// ============================================================

async function searchUsers(url, user, env) {
  const q = cleanText(
    url.searchParams.get("q") || "",
    80
  ).toLowerCase();

  if (!q) {
    return json({
      users: []
    });
  }

  const users = await env.DB.prepare(`
    SELECT
      id,
      username,
      display_name,
      bio,
      avatar_url
    FROM users
    WHERE
      LOWER(username) LIKE ?
      OR LOWER(display_name) LIKE ?
    ORDER BY username
    LIMIT 30
  `).bind(
    `%${q}%`,
    `%${q}%`
  ).all();

  return json({
    users: users.results || []
  });
}


// ============================================================
// FOLLOW
// ============================================================

async function toggleFollow(targetId, user, env) {
  if (targetId === user.id) {
    return json({
      error: "You cannot follow yourself."
    }, 400);
  }

  const target = await getUserById(targetId, env);

  if (!target) {
    return json({
      error: "User not found."
    }, 404);
  }

  const existing = await env.DB.prepare(`
    SELECT 1
    FROM follows
    WHERE follower_id = ? AND following_id = ?
    LIMIT 1
  `).bind(
    user.id,
    targetId
  ).first();

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM follows
      WHERE follower_id = ? AND following_id = ?
    `).bind(
      user.id,
      targetId
    ).run();

    return json({
      following: false
    });
  }

  await env.DB.prepare(`
    INSERT INTO follows
    (
      follower_id,
      following_id,
      created_at
    )
    VALUES (?, ?, ?)
  `).bind(
    user.id,
    targetId,
    now()
  ).run();

  await createNotification(
    targetId,
    user.id,
    "follow",
    null,
    env
  );

  return json({
    following: true
  });
}


// ============================================================
// FEED
// ============================================================

async function getFeed(user, env) {
  const result = await env.DB.prepare(`
    SELECT
      p.id,
      p.user_id,
      p.content,
      p.media_url,
      p.media_type,
      p.created_at,
      u.username,
      u.display_name,
      u.avatar_url,
      (
        SELECT COUNT(*)
        FROM likes l
        WHERE l.post_id = p.id
      ) AS likes,
      (
        SELECT COUNT(*)
        FROM comments c
        WHERE c.post_id = p.id
      ) AS comments,
      EXISTS(
        SELECT 1
        FROM likes l2
        WHERE l2.post_id = p.id
        AND l2.user_id = ?
      ) AS liked,
      EXISTS(
        SELECT 1
        FROM saved_posts s
        WHERE s.post_id = p.id
        AND s.user_id = ?
      ) AS saved
    FROM posts p
    JOIN users u ON u.id = p.user_id
    WHERE
      p.visibility = 'public'
      AND (
        p.user_id = ?
        OR EXISTS(
          SELECT 1
          FROM follows f
          WHERE f.follower_id = ?
          AND f.following_id = p.user_id
        )
      )
    ORDER BY p.created_at DESC
    LIMIT 100
  `).bind(
    user.id,
    user.id,
    user.id,
    user.id
  ).all();

  return json({
    posts: result.results || []
  });
}


// ============================================================
// POSTS
// ============================================================

async function createPost(request, user, env) {
  const body = await readJSON(request);

  const content =
    cleanText(body.content, 5000);

  const mediaUrl =
    cleanText(body.mediaUrl, 1000);

  const mediaType =
    cleanText(body.mediaType, 30);

  const visibility =
    body.visibility === "followers"
      ? "followers"
      : "public";

  if (!content && !mediaUrl) {
    return json({
      error: "Post cannot be empty."
    }, 400);
  }

  const id = crypto.randomUUID();

  await env.DB.prepare(`
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
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    user.id,
    content,
    mediaUrl,
    mediaType,
    visibility,
    now()
  ).run();

  return json({
    ok: true,
    post: {
      id,
      content,
      mediaUrl,
      mediaType,
      visibility
    }
  }, 201);
}


async function deletePost(id, user, env) {
  const post = await env.DB.prepare(`
    SELECT user_id
    FROM posts
    WHERE id = ?
    LIMIT 1
  `).bind(id).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  if (post.user_id !== user.id) {
    return json({
      error: "You can only delete your own posts."
    }, 403);
  }

  await env.DB.batch([
    env.DB.prepare(`DELETE FROM comments WHERE post_id = ?`).bind(id),
    env.DB.prepare(`DELETE FROM likes WHERE post_id = ?`).bind(id),
    env.DB.prepare(`DELETE FROM saved_posts WHERE post_id = ?`).bind(id),
    env.DB.prepare(`DELETE FROM posts WHERE id = ?`).bind(id)
  ]);

  return json({
    ok: true
  });
}


// ============================================================
// LIKES
// ============================================================

async function toggleLike(postId, user, env) {
  const post = await env.DB.prepare(`
    SELECT user_id
    FROM posts
    WHERE id = ?
    LIMIT 1
  `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  const existing = await env.DB.prepare(`
    SELECT 1
    FROM likes
    WHERE post_id = ? AND user_id = ?
    LIMIT 1
  `).bind(
    postId,
    user.id
  ).first();

  let liked;

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM likes
      WHERE post_id = ? AND user_id = ?
    `).bind(
      postId,
      user.id
    ).run();

    liked = false;

  } else {
    await env.DB.prepare(`
      INSERT INTO likes
      (
        post_id,
        user_id,
        created_at
      )
      VALUES (?, ?, ?)
    `).bind(
      postId,
      user.id,
      now()
    ).run();

    liked = true;

    if (post.user_id !== user.id) {
      await createNotification(
        post.user_id,
        user.id,
        "like",
        postId,
        env
      );
    }
  }

  const likes = await count(
    env.DB,
    `SELECT COUNT(*) AS n FROM likes WHERE post_id = ?`,
    postId
  );

  return json({
    liked,
    likes
  });
}


// ============================================================
// COMMENTS
// ============================================================

async function getComments(postId, env) {
  const result = await env.DB.prepare(`
    SELECT
      c.id,
      c.content,
      c.created_at,
      u.id AS user_id,
      u.username,
      u.display_name,
      u.avatar_url
    FROM comments c
    JOIN users u ON u.id = c.user_id
    WHERE c.post_id = ?
    ORDER BY c.created_at ASC
    LIMIT 200
  `).bind(postId).all();

  return json({
    comments: result.results || []
  });
}


async function createComment(postId, request, user, env) {
  const body = await readJSON(request);

  const content =
    cleanText(body.content, 1000);

  if (!content) {
    return json({
      error: "Comment cannot be empty."
    }, 400);
  }

  const post = await env.DB.prepare(`
    SELECT user_id
    FROM posts
    WHERE id = ?
    LIMIT 1
  `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  const id = crypto.randomUUID();

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
    id,
    postId,
    user.id,
    content,
    now()
  ).run();

  if (post.user_id !== user.id) {
    await createNotification(
      post.user_id,
      user.id,
      "comment",
      postId,
      env
    );
  }

  return json({
    ok: true,
    comment: {
      id,
      content,
      username: user.username,
      displayName: user.display_name,
      createdAt: now()
    }
  }, 201);
}


// ============================================================
// SAVED POSTS
// ============================================================

async function toggleSave(postId, user, env) {
  const existing = await env.DB.prepare(`
    SELECT 1
    FROM saved_posts
    WHERE post_id = ? AND user_id = ?
    LIMIT 1
  `).bind(
    postId,
    user.id
  ).first();

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM saved_posts
      WHERE post_id = ? AND user_id = ?
    `).bind(
      postId,
      user.id
    ).run();

    return json({
      saved: false
    });
  }

  await env.DB.prepare(`
    INSERT INTO saved_posts
    (
      post_id,
      user_id,
      created_at
    )
    VALUES (?, ?, ?)
  `).bind(
    postId,
    user.id,
    now()
  ).run();

  return json({
    saved: true
  });
}


// ============================================================
// MEDIA / R2 (optional – requires MEDIA binding)
// ============================================================

async function uploadMedia(request, user, env) {
  if (!env.MEDIA) {
    return json({
      error: "Media storage is not configured."
    }, 500);
  }

  const form = await request.formData();
  const file = form.get("file");

  if (!(file instanceof File)) {
    return json({
      error: "No file received."
    }, 400);
  }

  const maxImage = 10 * 1024 * 1024;
  const maxVideo = 100 * 1024 * 1024;

  const isImage = file.type.startsWith("image/");
  const isVideo = file.type.startsWith("video/");

  if (!isImage && !isVideo) {
    return json({
      error: "Only image and video files are allowed."
    }, 400);
  }

  if (isImage && file.size > maxImage) {
    return json({
      error: "Image is too large. Maximum 10 MB."
    }, 400);
  }

  if (isVideo && file.size > maxVideo) {
    return json({
      error: "Video is too large. Maximum 100 MB."
    }, 400);
  }

  const extension =
    getExtension(file.name, file.type);

  const key =
    `${user.id}/${Date.now()}-${randomToken(12)}.${extension}`;

  await env.MEDIA.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType: file.type,
        cacheControl: "public, max-age=31536000, immutable"
      },
      customMetadata: {
        userId: user.id
      }
    }
  );

  return json({
    ok: true,
    key,
    url: `/media/${key}`,
    type: file.type
  });
}


async function serveMedia(request, env, url) {
  if (!env.MEDIA) {
    return new Response("Media storage unavailable.", {
      status: 503
    });
  }

  const key =
    decodeURIComponent(
      url.pathname.substring("/media/".length)
    );

  if (!key) {
    return new Response("Not found", {
      status: 404
    });
  }

  const object = await env.MEDIA.get(key);

  if (!object) {
    return new Response("Not found", {
      status: 404
    });
  }

  const headers = new Headers();

  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set(
    "Cache-Control",
    "public, max-age=31536000, immutable"
  );

  return new Response(object.body, {
    headers
  });
}


// ============================================================
// STORIES
// ============================================================

async function createStory(request, user, env) {
  const body = await readJSON(request);

  const mediaUrl =
    cleanText(body.mediaUrl, 1000);

  const text =
    cleanText(body.text, 500);

  if (!mediaUrl && !text) {
    return json({
      error: "Story cannot be empty."
    }, 400);
  }

  const id = crypto.randomUUID();

  const expires =
    Date.now() + 24 * 60 * 60 * 1000;

  await env.DB.prepare(`
    INSERT INTO stories
    (
      id,
      user_id,
      text,
      media_url,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    user.id,
    text,
    mediaUrl,
    now(),
    expires
  ).run();

  return json({
    ok: true,
    story: {
      id,
      text,
      mediaUrl
    }
  }, 201);
}


async function getStoryFeed(user, env) {
  const result = await env.DB.prepare(`
    SELECT
      s.id,
      s.user_id,
      s.text,
      s.media_url,
      s.created_at,
      s.expires_at,
      u.username,
      u.display_name,
      u.avatar_url
    FROM stories s
    JOIN users u ON u.id = s.user_id
    WHERE
      s.expires_at > ?
      AND (
        s.user_id = ?
        OR EXISTS(
          SELECT 1
          FROM follows f
          WHERE f.follower_id = ?
          AND f.following_id = s.user_id
        )
      )
    ORDER BY s.created_at DESC
    LIMIT 100
  `).bind(
    Date.now(),
    user.id,
    user.id
  ).all();

  return json({
    stories: result.results || []
  });
}


// ============================================================
// REELS
// ============================================================

async function createReel(request, user, env) {
  const body = await readJSON(request);

  const videoUrl =
    cleanText(body.videoUrl, 1000);

  const caption =
    cleanText(body.caption, 2000);

  if (!videoUrl) {
    return json({
      error: "Video is required."
    }, 400);
  }

  const id = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO reels
    (
      id,
      user_id,
      video_url,
      caption,
      created_at
    )
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    id,
    user.id,
    videoUrl,
    caption,
    now()
  ).run();

  return json({
    ok: true,
    reel: {
      id,
      videoUrl,
      caption
    }
  }, 201);
}


async function getReels(user, env) {
  const result = await env.DB.prepare(`
    SELECT
      r.id,
      r.user_id,
      r.video_url,
      r.caption,
      r.created_at,
      u.username,
      u.display_name,
      u.avatar_url
    FROM reels r
    JOIN users u ON u.id = r.user_id
    ORDER BY r.created_at DESC
    LIMIT 100
  `).all();

  return json({
    reels: result.results || []
  });
}


// ============================================================
// CHAT
// ============================================================

async function getChats(user, env) {
  const result = await env.DB.prepare(`
    SELECT
      c.id,
      c.type,
      c.name,
      c.created_at
    FROM chats c
    JOIN chat_members cm
      ON cm.chat_id = c.id
    WHERE cm.user_id = ?
    ORDER BY c.created_at DESC
  `).bind(user.id).all();

  return json({
    chats: result.results || []
  });
}


async function createChat(request, user, env) {
  const body = await readJSON(request);

  const targetUserId =
    cleanText(body.userId, 100);

  if (!targetUserId || targetUserId === user.id) {
    return json({
      error: "Invalid user."
    }, 400);
  }

  const target = await getUserById(
    targetUserId,
    env
  );

  if (!target) {
    return json({
      error: "User not found."
    }, 404);
  }

  // Find existing one-to-one chat.
  const existing = await env.DB.prepare(`
    SELECT c.id
    FROM chats c
    JOIN chat_members a
      ON a.chat_id = c.id
    JOIN chat_members b
      ON b.chat_id = c.id
    WHERE
      c.type = 'direct'
      AND a.user_id = ?
      AND b.user_id = ?
    LIMIT 1
  `).bind(
    user.id,
    targetUserId
  ).first();

  if (existing) {
    return json({
      chatId: existing.id
    });
  }

  const chatId = crypto.randomUUID();

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO chats
      (
        id,
        type,
        name,
        created_at
      )
      VALUES (?, 'direct', '', ?)
    `).bind(chatId, now()),

    env.DB.prepare(`
      INSERT INTO chat_members
      (
        chat_id,
        user_id,
        joined_at
      )
      VALUES (?, ?, ?)
    `).bind(chatId, user.id, now()),

    env.DB.prepare(`
      INSERT INTO chat_members
      (
        chat_id,
        user_id,
        joined_at
      )
      VALUES (?, ?, ?)
    `).bind(chatId, targetUserId, now())
  ]);

  return json({
    ok: true,
    chatId
  }, 201);
}


async function getMessages(chatId, user, env) {
  if (!(await isChatMember(chatId, user.id, env))) {
    return json({
      error: "You are not a member of this chat."
    }, 403);
  }

  const result = await env.DB.prepare(`
    SELECT
      m.id,
      m.chat_id,
      m.user_id,
      m.content,
      m.media_url,
      m.created_at,
      u.username,
      u.display_name,
      u.avatar_url
    FROM messages m
    JOIN users u ON u.id = m.user_id
    WHERE m.chat_id = ?
    ORDER BY m.created_at ASC
    LIMIT 500
  `).bind(chatId).all();

  return json({
    messages: result.results || []
  });
}


async function sendMessage(chatId, request, user, env) {
  if (!(await isChatMember(chatId, user.id, env))) {
    return json({
      error: "You are not a member of this chat."
    }, 403);
  }

  const body = await readJSON(request);

  const content =
    cleanText(body.content, 5000);

  const mediaUrl =
    cleanText(body.mediaUrl, 1000);

  if (!content && !mediaUrl) {
    return json({
      error: "Message cannot be empty."
    }, 400);
  }

  const id = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO messages
    (
      id,
      chat_id,
      user_id,
      content,
      media_url,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    chatId,
    user.id,
    content,
    mediaUrl,
    now()
  ).run();

  return json({
    ok: true,
    message: {
      id,
      chatId,
      userId: user.id,
      content,
      mediaUrl,
      createdAt: now()
    }
  }, 201);
}


// ============================================================
// GROUP CHAT
// ============================================================

async function createGroup(request, user, env) {
  const body = await readJSON(request);

  const name =
    cleanText(body.name, 100);

  const members =
    Array.isArray(body.members)
      ? body.members
      : [];

  if (!name) {
    return json({
      error: "Group name is required."
    }, 400);
  }

  const memberIds =
    [...new Set([
      user.id,
      ...members.map(x => String(x))
    ])];

  if (memberIds.length < 2) {
    return json({
      error: "Add at least one other member."
    }, 400);
  }

  const chatId = crypto.randomUUID();

  const statements = [
    env.DB.prepare(`
      INSERT INTO chats
      (
        id,
        type,
        name,
        created_at
      )
      VALUES (?, 'group', ?, ?)
    `).bind(
      chatId,
      name,
      now()
    )
  ];

  for (const memberId of memberIds) {
    statements.push(
      env.DB.prepare(`
        INSERT INTO chat_members
        (
          chat_id,
          user_id,
          joined_at
        )
        VALUES (?, ?, ?)
      `).bind(
        chatId,
        memberId,
        now()
      )
    );
  }

  await env.DB.batch(statements);

  return json({
    ok: true,
    chatId
  }, 201);
}


// ============================================================
// NOTIFICATIONS
// ============================================================

async function createNotification(
  userId,
  actorId,
  type,
  postId,
  env
) {
  await env.DB.prepare(`
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
    VALUES (?, ?, ?, ?, ?, 0, ?)
  `).bind(
    crypto.randomUUID(),
    userId,
    actorId,
    type,
    postId,
    now()
  ).run();
}


async function getNotifications(user, env) {
  const result = await env.DB.prepare(`
    SELECT
      n.id,
      n.type,
      n.post_id,
      n.is_read,
      n.created_at,
      u.username,
      u.display_name,
      u.avatar_url
    FROM notifications n
    JOIN users u
      ON u.id = n.actor_id
    WHERE n.user_id = ?
    ORDER BY n.created_at DESC
    LIMIT 100
  `).bind(user.id).all();

  return json({
    notifications: result.results || []
  });
}


async function markNotificationsRead(user, env) {
  await env.DB.prepare(`
    UPDATE notifications
    SET is_read = 1
    WHERE user_id = ?
  `).bind(user.id).run();

  return json({
    ok: true
  });
}


// ============================================================
// SETTINGS
// ============================================================

async function getSettings(user, env) {
  const row = await env.DB.prepare(`
    SELECT
      theme,
      profile_visibility,
      message_privacy,
      notification_settings
    FROM user_settings
    WHERE user_id = ?
    LIMIT 1
  `).bind(user.id).first();

  return json({
    settings: row || {
      theme: "system",
      profile_visibility: "public",
      message_privacy: "everyone",
      notification_settings: "{}"
    }
  });
}


async function updateSettings(request, user, env) {
  const body = await readJSON(request);

  const theme =
    ["light", "dark", "system"].includes(body.theme)
      ? body.theme
      : "system";

  const profileVisibility =
    ["public", "followers", "private"].includes(
      body.profileVisibility
    )
      ? body.profileVisibility
      : "public";

  const messagePrivacy =
    ["everyone", "followers", "nobody"].includes(
      body.messagePrivacy
    )
      ? body.messagePrivacy
      : "everyone";

  const notifications =
    JSON.stringify(
      body.notifications || {}
    );

  await env.DB.prepare(`
    INSERT INTO user_settings
    (
      user_id,
      theme,
      profile_visibility,
      message_privacy,
      notification_settings
    )
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id)
    DO UPDATE SET
      theme = excluded.theme,
      profile_visibility = excluded.profile_visibility,
      message_privacy = excluded.message_privacy,
      notification_settings = excluded.notification_settings
  `).bind(
    user.id,
    theme,
    profileVisibility,
    messagePrivacy,
    notifications
  ).run();

  return json({
    ok: true
  });
}


// ============================================================
// SESSION AUTHENTICATION
// ============================================================

async function requireUser(request, env) {
  const token =
    getCookie(request, SESSION_COOKIE);

  if (!token) return null;

  const tokenHash =
    await sha256(token);

  const session = await env.DB.prepare(`
    SELECT
      s.user_id,
      s.expires_at
    FROM sessions s
    WHERE s.token_hash = ?
    LIMIT 1
  `).bind(tokenHash).first();

  if (!session) {
    return null;
  }

  if (Number(session.expires_at) < Date.now()) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `).bind(tokenHash).run();

    return null;
  }

  return getUserById(
    session.user_id,
    env
  );
}


async function createSession(userId, env) {
  const rawToken =
    randomToken(48);

  const tokenHash =
    await sha256(rawToken);

  const expiresAt =
    Date.now() +
    SESSION_DAYS * 24 * 60 * 60 * 1000;

  await env.DB.prepare(`
    INSERT INTO sessions
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
    userId,
    tokenHash,
    expiresAt,
    now()
  ).run();

  return rawToken;
}


// ============================================================
// PASSWORD HASHING (single correct PBKDF2 implementation)
// ============================================================

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
    const parts = stored.split("$");

    if (parts.length !== 4) {
      return false;
    }

    const iterations =
      Number(parts[1]);

    const salt =
      base64ToBytes(parts[2]);

    const expected =
      base64ToBytes(parts[3]);

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

  } catch {
    return false;
  }
}


// ============================================================
// RESEND PASSWORD EMAIL
// ============================================================

async function sendResetEmail(
  env,
  email,
  resetURL
) {
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
        from: env.RESET_FROM_EMAIL,
        to: [email],
        subject: "Reset your Zilnet password",
        html: `
          <div style="font-family:Arial,sans-serif">
            <h2>Zilnet password reset</h2>

            <p>
              Someone requested a password reset
              for your Zilnet account.
            </p>

            <p>
              <a href="${escapeHTML(resetURL)}">
                Reset your password
              </a>
            </p>

            <p>
              This link expires in 30 minutes.
            </p>
          </div>
        `
      })
    }
  );
}


// ============================================================
// DATABASE HELPERS
// ============================================================

async function getUserById(id, env) {
  return env.DB.prepare(`
    SELECT *
    FROM users
    WHERE id = ?
    LIMIT 1
  `).bind(id).first();
}


async function isChatMember(chatId, userId, env) {
  const row = await env.DB.prepare(`
    SELECT 1
    FROM chat_members
    WHERE chat_id = ? AND user_id = ?
    LIMIT 1
  `).bind(
    chatId,
    userId
  ).first();

  return !!row;
}


async function count(db, sql, value) {
  const row =
    await db.prepare(sql)
      .bind(value)
      .first();

  return Number(row?.n || 0);
}


// ============================================================
// UTILITIES
// ============================================================

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    email: user.email,
    bio: user.bio || "",
    skills: parseSkills(user.skills),
    avatarUrl: user.avatar_url || "",
    createdAt: user.created_at
  };
}


function parseSkills(value) {
  if (!value) return [];

  try {
    const parsed = JSON.parse(value);

    return Array.isArray(parsed)
      ? parsed
      : [];
  } catch {
    return value
      .split(",")
      .map(x => x.trim())
      .filter(Boolean);
  }
}


function cleanUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}


function cleanEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}


function cleanText(value, max) {
  return String(value || "")
    .trim()
    .slice(0, max);
}


async function readJSON(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}


function now() {
  return new Date().toISOString();
}


function randomToken(length = 32) {
  const bytes =
    crypto.getRandomValues(
      new Uint8Array(length)
    );

  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}


async function sha256(value) {
  const data =
    new TextEncoder().encode(value);

  const hash =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return bytesToBase64(
    new Uint8Array(hash)
  );
}


function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}


function base64ToBytes(value) {
  const binary =
    atob(value);

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


function getCookie(request, name) {
  const cookie =
    request.headers.get("Cookie") || "";

  const parts =
    cookie.split(";");

  for (const part of parts) {
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


function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=utf-8",
        "Cache-Control":
          "no-store"
      }
    }
  );
}


function getExtension(filename, type) {
  const match =
    String(filename || "")
      .match(/\.([a-zA-Z0-9]+)$/);

  if (match) {
    return match[1].toLowerCase();
  }

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


function escapeHTML(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
