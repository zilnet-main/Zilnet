// ============================================================
// ZILNET BACKEND
// Cloudflare Worker + D1 + optional R2
// ============================================================

const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 150000;
const SESSION_COOKIE = "zilnet_session";

// ============================================================
// HTTP ERROR
// ============================================================

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ============================================================
// MAIN
// ============================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname.startsWith("/api/")) {
        return await api(request, env, url);
      }

      if (url.pathname.startsWith("/media/")) {
        return await serveMedia(request, env, url);
      }

      if (!env.ASSETS) {
        return new Response("Static assets are not configured.", {
          status: 503
        });
      }

      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error(error);

      if (error instanceof HttpError) {
        return json({
          error: error.message
        }, error.status);
      }

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

  // ==========================================================
  // PUBLIC AUTH
  // ==========================================================

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

  // ==========================================================
  // AUTH REQUIRED
  // ==========================================================

  const user = await requireUser(request, env);

  if (!user) {
    return json({
      error: "Authentication required"
    }, 401);
  }

  // ==========================================================
  // PROFILE
  // ==========================================================

  if (method === "GET" && path === "/api/profile") {
    return getProfile(user, env);
  }

  if (method === "PUT" && path === "/api/profile/update") {
    return updateProfile(request, user, env);
  }

  if (
    method === "GET" &&
    path.startsWith("/api/profile/")
  ) {
    const username = decodeURIComponent(
      path.substring("/api/profile/".length)
    );

    return getPublicProfile(username, user, env);
  }

  // ==========================================================
  // SEARCH
  // ==========================================================

  if (method === "GET" && path === "/api/search") {
    return searchUsers(url, user, env);
  }

  // ==========================================================
  // FOLLOW
  // ==========================================================

  if (
    method === "POST" &&
    /^\/api\/users\/[^/]+\/follow$/.test(path)
  ) {
    const id = parseId(path.split("/")[3]);

    if (id === null) {
      return json({
        error: "Invalid user ID"
      }, 400);
    }

    return toggleFollow(id, user, env);
  }

  // ==========================================================
  // FEED
  // ==========================================================

  if (method === "GET" && path === "/api/feed") {
    return getFeed(user, env);
  }

  // ==========================================================
  // POSTS
  // ==========================================================

  if (method === "POST" && path === "/api/posts") {
    return createPost(request, user, env);
  }

  if (
    method === "DELETE" &&
    /^\/api\/posts\/[^/]+$/.test(path)
  ) {
    const id = parseId(path.split("/")[3]);

    if (id === null) {
      return json({
        error: "Invalid post ID"
      }, 400);
    }

    return deletePost(id, user, env);
  }

  if (
    method === "POST" &&
    /^\/api\/posts\/[^/]+\/like$/.test(path)
  ) {
    const id = parseId(path.split("/")[3]);

    if (id === null) {
      return json({
        error: "Invalid post ID"
      }, 400);
    }

    return toggleLike(id, user, env);
  }

  if (
    method === "GET" &&
    /^\/api\/posts\/[^/]+\/comments$/.test(path)
  ) {
    const id = parseId(path.split("/")[3]);

    if (id === null) {
      return json({
        error: "Invalid post ID"
      }, 400);
    }

    return getComments(id, env);
  }

  if (
    method === "POST" &&
    /^\/api\/posts\/[^/]+\/comments$/.test(path)
  ) {
    const id = parseId(path.split("/")[3]);

    if (id === null) {
      return json({
        error: "Invalid post ID"
      }, 400);
    }

    return createComment(id, request, user, env);
  }

  if (
    method === "POST" &&
    /^\/api\/posts\/[^/]+\/save$/.test(path)
  ) {
    const id = parseId(path.split("/")[3]);

    if (id === null) {
      return json({
        error: "Invalid post ID"
      }, 400);
    }

    return toggleSave(id, user, env);
  }

  // ==========================================================
  // UPLOAD
  // ==========================================================

  if (method === "POST" && path === "/api/upload") {
    return uploadMedia(request, user, env);
  }

  // ==========================================================
  // STORIES
  // ==========================================================

  if (method === "GET" && path === "/api/stories/feed") {
    return getStoryFeed(user, env);
  }

  if (method === "POST" && path === "/api/stories") {
    return createStory(request, user, env);
  }

  // ==========================================================
  // REELS
  // ==========================================================

  if (method === "GET" && path === "/api/reels/feed") {
    return getReels(user, env);
  }

  if (method === "POST" && path === "/api/reels") {
    return createReel(request, user, env);
  }

  // ==========================================================
  // CHATS
  // ==========================================================

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
    const chatId = parseId(path.split("/")[3]);

    if (chatId === null) {
      return json({
        error: "Invalid chat ID"
      }, 400);
    }

    return getMessages(chatId, user, env);
  }

  if (
    method === "POST" &&
    /^\/api\/chats\/[^/]+\/messages$/.test(path)
  ) {
    const chatId = parseId(path.split("/")[3]);

    if (chatId === null) {
      return json({
        error: "Invalid chat ID"
      }, 400);
    }

    return sendMessage(chatId, request, user, env);
  }

  // ==========================================================
  // GROUPS
  // ==========================================================

  if (method === "POST" && path === "/api/groups") {
    return createGroup(request, user, env);
  }

  // ==========================================================
  // NOTIFICATIONS
  // ==========================================================

  if (method === "GET" && path === "/api/notifications") {
    return getNotifications(user, env);
  }

  if (method === "POST" && path === "/api/notifications/read") {
    return markNotificationsRead(user, env);
  }

  // ==========================================================
  // SETTINGS
  // ==========================================================

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

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
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
    WHERE LOWER(username) = ? OR LOWER(email) = ?
    LIMIT 1
  `).bind(
    username,
    email
  ).first();

  if (existing) {
    return json({
      error: "Username or email is already registered."
    }, 409);
  }

  const passwordHash = await hashPassword(password);

  let result;

  try {
    result = await env.DB.prepare(`
      INSERT INTO users
      (
        username,
        display_name,
        email,
        password_hash,
        bio,
        skills,
        avatar_url
      )
      VALUES (?, ?, ?, ?, '', '', '')
    `).bind(
      username,
      displayName,
      email,
      passwordHash
    ).run();
  } catch (error) {
    console.error("Signup insert failed:", error);

    return json({
      error: "Username or email is already registered."
    }, 409);
  }

  const userId = Number(result.meta?.last_row_id);

  if (!Number.isSafeInteger(userId) || userId <= 0) {
    throw new Error("Could not obtain new user ID.");
  }

  const token = await createSession(userId, env);

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
    }),
    makeSessionCookie(token)
  );
}

// ============================================================

async function login(request, env) {
  const body = await readJSON(request);

  const loginValue =
    cleanText(body.login, 100).toLowerCase();

  const password =
    String(body.password || "");

  if (!loginValue || !password) {
    return json({
      error: "Enter your username/email and password."
    }, 400);
  }

  const user = await env.DB.prepare(`
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

  const token = await createSession(
    user.id,
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

// ============================================================

async function logout(request, env) {
  const token =
    getCookie(request, SESSION_COOKIE);

  if (token) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `).bind(token).run();
  }

  return withCookie(
    json({
      ok: true
    }),
    clearSessionCookie()
  );
}

// ============================================================

async function getMe(request, env) {
  const user =
    await requireUser(request, env);

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

  const email =
    cleanEmail(body.email);

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

  if (!user) {
    return json({
      ok: true,
      message: "If an account exists, a reset email will be sent."
    });
  }

  const rawToken =
    randomToken(48);

  const tokenHash =
    await sha256(rawToken);

  const expires =
    Date.now() + 30 * 60 * 1000;

  const userId =
    String(user.id);

  await env.DB.prepare(`
    DELETE FROM password_resets
    WHERE user_id = ?
  `).bind(userId).run();

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
    userId,
    tokenHash,
    expires,
    now()
  ).run();

  if (
    env.RESEND_API_KEY &&
    env.RESET_FROM_EMAIL
  ) {
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

// ============================================================

async function resetPassword(request, env) {
  const body = await readJSON(request);

  const token =
    String(body.token || "");

  const newPassword =
    String(body.password || "");

  if (!token || newPassword.length < 8) {
    return json({
      error: "Invalid reset request."
    }, 400);
  }

  const tokenHash =
    await sha256(token);

  const reset =
    await env.DB.prepare(`
      SELECT *
      FROM password_resets
      WHERE token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

  if (
    !reset ||
    Number(reset.expires_at) < Date.now()
  ) {
    return json({
      error: "This reset link is invalid or expired."
    }, 400);
  }

  const targetUserId =
    parseId(reset.user_id);

  if (targetUserId === null) {
    return json({
      error: "Invalid reset record."
    }, 400);
  }

  const passwordHash =
    await hashPassword(newPassword);

  const result =
    await env.DB.prepare(`
      UPDATE users
      SET password_hash = ?
      WHERE id = ?
    `).bind(
      passwordHash,
      targetUserId
    ).run();

  if (!result.success) {
    throw new Error("Password update failed.");
  }

  await env.DB.prepare(`
    DELETE FROM sessions
    WHERE user_id = ?
  `).bind(targetUserId).run();

  await env.DB.prepare(`
    DELETE FROM password_resets
    WHERE user_id = ?
  `).bind(String(targetUserId)).run();

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

// ============================================================

async function getPublicProfile(
  username,
  currentUser,
  env
) {
  const profile =
    await env.DB.prepare(`
      SELECT
        id,
        username,
        display_name,
        bio,
        skills,
        avatar_url,
        created_at,
        is_private
      FROM users
      WHERE LOWER(username) = ?
      LIMIT 1
    `).bind(
      username.toLowerCase()
    ).first();

  if (!profile) {
    return json({
      error: "User not found."
    }, 404);
  }

  const followers =
    await count(
      env.DB,
      `SELECT COUNT(*) AS n
       FROM follows
       WHERE following_id = ?`,
      profile.id
    );

  const following =
    await count(
      env.DB,
      `SELECT COUNT(*) AS n
       FROM follows
       WHERE follower_id = ?`,
      profile.id
    );

  const followRow =
    await env.DB.prepare(`
      SELECT 1
      FROM follows
      WHERE follower_id = ?
        AND following_id = ?
      LIMIT 1
    `).bind(
      currentUser.id,
      profile.id
    ).first();

  const isFollowing =
    !!followRow;

  const isSelf =
    Number(currentUser.id) === Number(profile.id);

  const canSeePrivateDetails =
    isSelf ||
    !profile.is_private ||
    isFollowing;

  return json({
    profile: {
      id: profile.id,
      username: profile.username,
      displayName: profile.display_name || "",
      avatarUrl: profile.avatar_url || "",
      createdAt: profile.created_at,
      isPrivate: !!profile.is_private,
      bio: canSeePrivateDetails
        ? (profile.bio || "")
        : "",
      skills: canSeePrivateDetails
        ? parseSkills(profile.skills)
        : [],
      followers,
      following,
      isFollowing
    }
  });
}

// ============================================================

async function updateProfile(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const displayName =
    body.displayName !== undefined
      ? cleanText(body.displayName, 80)
      : (user.display_name || "");

  const bio =
    body.bio !== undefined
      ? cleanText(body.bio, 500)
      : (user.bio || "");

  const skills =
    Array.isArray(body.skills)
      ? body.skills
          .map(x => cleanText(x, 40))
          .filter(Boolean)
          .slice(0, 20)
      : parseSkills(user.skills);

  const avatarUrl =
    body.avatarUrl !== undefined
      ? cleanText(body.avatarUrl, 500)
      : (user.avatar_url || "");

  const isPrivate =
    body.isPrivate !== undefined
      ? (body.isPrivate ? 1 : 0)
      : Number(user.is_private || 0);

  await env.DB.prepare(`
    UPDATE users
    SET
      display_name = ?,
      bio = ?,
      skills = ?,
      avatar_url = ?,
      is_private = ?
    WHERE id = ?
  `).bind(
    displayName,
    bio,
    JSON.stringify(skills),
    avatarUrl,
    isPrivate,
    user.id
  ).run();

  const updated =
    await getUserById(user.id, env);

  return json({
    ok: true,
    user: publicUser(updated)
  });
}

// ============================================================
// SEARCH
// ============================================================

async function searchUsers(
  url,
  user,
  env
) {
  const q =
    cleanText(
      url.searchParams.get("q") || "",
      80
    ).toLowerCase();

  if (!q) {
    return json({
      users: []
    });
  }

  const result =
    await env.DB.prepare(`
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
    users: result.results || []
  });
}

// ============================================================
// FOLLOW
// ============================================================

async function toggleFollow(
  targetId,
  user,
  env
) {
  if (Number(targetId) === Number(user.id)) {
    return json({
      error: "You cannot follow yourself."
    }, 400);
  }

  const target =
    await getUserById(targetId, env);

  if (!target) {
    return json({
      error: "User not found."
    }, 404);
  }

  const existing =
    await env.DB.prepare(`
      SELECT 1
      FROM follows
      WHERE follower_id = ?
        AND following_id = ?
      LIMIT 1
    `).bind(
      user.id,
      targetId
    ).first();

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM follows
      WHERE follower_id = ?
        AND following_id = ?
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
      following_id
    )
    VALUES (?, ?)
    ON CONFLICT(follower_id, following_id)
    DO NOTHING
  `).bind(
    user.id,
    targetId
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
  const result =
    await env.DB.prepare(`
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
          WHERE s.post_id = CAST(p.id AS TEXT)
            AND s.user_id = ?
        ) AS saved

      FROM posts p

      JOIN users u
        ON u.id = p.user_id

      WHERE
        p.user_id = ?

        OR EXISTS(
          SELECT 1
          FROM follows f
          WHERE f.follower_id = ?
            AND f.following_id = p.user_id
        )

      ORDER BY p.created_at DESC
      LIMIT 100
    `).bind(
      user.id,
      String(user.id),
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

async function createPost(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const content =
    cleanText(body.content, 5000);

  const mediaUrl =
    cleanText(body.mediaUrl, 1000);

  const mediaType =
    cleanText(body.mediaType, 30);

  if (!content && !mediaUrl) {
    return json({
      error: "Post cannot be empty."
    }, 400);
  }

  const result =
    await env.DB.prepare(`
      INSERT INTO posts
      (
        user_id,
        content,
        media_url,
        media_type
      )
      VALUES (?, ?, ?, ?)
    `).bind(
      user.id,
      content,
      mediaUrl,
      mediaType
    ).run();

  const postId =
    Number(result.meta?.last_row_id);

  return json({
    ok: true,
    post: {
      id: postId,
      userId: user.id,
      content,
      mediaUrl,
      mediaType,
      createdAt: now()
    }
  }, 201);
}

// ============================================================

async function deletePost(
  id,
  user,
  env
) {
  const post =
    await env.DB.prepare(`
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

  if (
    Number(post.user_id) !== Number(user.id)
  ) {
    return json({
      error: "You can only delete your own posts."
    }, 403);
  }

  const strPostId =
    String(id);

  await env.DB.batch([
    env.DB.prepare(`
      DELETE FROM comments
      WHERE post_id = ?
    `).bind(id),

    env.DB.prepare(`
      DELETE FROM likes
      WHERE post_id = ?
    `).bind(id),

    env.DB.prepare(`
      DELETE FROM saved_posts
      WHERE post_id = ?
    `).bind(strPostId),

    env.DB.prepare(`
      DELETE FROM notifications
      WHERE post_id = ?
    `).bind(id),

    env.DB.prepare(`
      DELETE FROM posts
      WHERE id = ?
    `).bind(id)
  ]);

  return json({
    ok: true
  });
}

// ============================================================
// LIKES
// ============================================================

async function toggleLike(
  postId,
  user,
  env
) {
  const post =
    await env.DB.prepare(`
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

  const existing =
    await env.DB.prepare(`
      SELECT 1
      FROM likes
      WHERE post_id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      postId,
      user.id
    ).first();

  let liked;

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM likes
      WHERE post_id = ?
        AND user_id = ?
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
        user_id
      )
      VALUES (?, ?)
      ON CONFLICT(post_id, user_id)
      DO NOTHING
    `).bind(
      postId,
      user.id
    ).run();

    liked = true;

    if (
      Number(post.user_id) !== Number(user.id)
    ) {
      await createNotification(
        post.user_id,
        user.id,
        "like",
        postId,
        env
      );
    }
  }

  const likes =
    await count(
      env.DB,
      `SELECT COUNT(*) AS n
       FROM likes
       WHERE post_id = ?`,
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

async function getComments(
  postId,
  env
) {
  const post =
    await env.DB.prepare(`
      SELECT id
      FROM posts
      WHERE id = ?
      LIMIT 1
    `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  const result =
    await env.DB.prepare(`
      SELECT
        c.id,
        c.content,
        c.created_at,

        u.id AS user_id,
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
    comments: result.results || []
  });
}

// ============================================================

async function createComment(
  postId,
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const content =
    cleanText(body.content, 1000);

  if (!content) {
    return json({
      error: "Comment cannot be empty."
    }, 400);
  }

  const post =
    await env.DB.prepare(`
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

  const result =
    await env.DB.prepare(`
      INSERT INTO comments
      (
        post_id,
        user_id,
        content
      )
      VALUES (?, ?, ?)
    `).bind(
      postId,
      user.id,
      content
    ).run();

  const commentId =
    Number(result.meta?.last_row_id);

  if (
    Number(post.user_id) !== Number(user.id)
  ) {
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
      id: commentId,
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

async function toggleSave(
  postId,
  user,
  env
) {
  const post =
    await env.DB.prepare(`
      SELECT id
      FROM posts
      WHERE id = ?
      LIMIT 1
    `).bind(postId).first();

  if (!post) {
    return json({
      error: "Post not found."
    }, 404);
  }

  const savedPostId =
    String(postId);

  const savedUserId =
    String(user.id);

  const existing =
    await env.DB.prepare(`
      SELECT 1
      FROM saved_posts
      WHERE post_id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      savedPostId,
      savedUserId
    ).first();

  if (existing) {
    await env.DB.prepare(`
      DELETE FROM saved_posts
      WHERE post_id = ?
        AND user_id = ?
    `).bind(
      savedPostId,
      savedUserId
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
    ON CONFLICT(post_id, user_id)
    DO NOTHING
  `).bind(
    savedPostId,
    savedUserId,
    now()
  ).run();

  return json({
    saved: true
  });
}

// ============================================================
// MEDIA / R2
// ============================================================

async function uploadMedia(
  request,
  user,
  env
) {
  if (!env.MEDIA) {
    return json({
      error: "Media storage is not configured."
    }, 500);
  }

  let form;

  try {
    form =
      await request.formData();
  } catch {
    return json({
      error: "Invalid form data."
    }, 400);
  }

  const file =
    form.get("file");

  if (!(file instanceof File)) {
    return json({
      error: "No file received."
    }, 400);
  }

  const maxImage =
    10 * 1024 * 1024;

  const maxVideo =
    100 * 1024 * 1024;

  const isImage =
    file.type.startsWith("image/");

  const isVideo =
    file.type.startsWith("video/");

  if (!isImage && !isVideo) {
    return json({
      error: "Only image and video files are allowed."
    }, 400);
  }

  if (
    isImage &&
    file.size > maxImage
  ) {
    return json({
      error: "Image is too large. Maximum 10 MB."
    }, 400);
  }

  if (
    isVideo &&
    file.size > maxVideo
  ) {
    return json({
      error: "Video is too large. Maximum 100 MB."
    }, 400);
  }

  const extension =
    getExtension(
      file.name,
      file.type
    );

  const key =
    `${user.id}/${Date.now()}-${randomToken(12)}.${extension}`;

  await env.MEDIA.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType: file.type,
        cacheControl:
          "public, max-age=31536000, immutable"
      },

      customMetadata: {
        userId: String(user.id)
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

// ============================================================

async function serveMedia(
  request,
  env,
  url
) {
  if (!env.MEDIA) {
    return new Response(
      "Media storage unavailable.",
      { status: 503 }
    );
  }

  let key;

  try {
    key =
      decodeURIComponent(
        url.pathname.substring(
          "/media/".length
        )
      );
  } catch {
    return new Response(
      "Invalid media path.",
      { status: 400 }
    );
  }

  if (!key) {
    return new Response(
      "Not found",
      { status: 404 }
    );
  }

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

  object.writeHttpMetadata(headers);

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
    { headers }
  );
}

// ============================================================
// STORIES
// ============================================================

async function createStory(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const mediaUrl =
    cleanText(body.mediaUrl, 1000);

  // Support both API names.
  const content =
    cleanText(
      body.content !== undefined
        ? body.content
        : body.text,
      500
    );

  const mediaType =
    cleanText(body.mediaType, 30);

  if (!mediaUrl && !content) {
    return json({
      error: "Story cannot be empty."
    }, 400);
  }

  const result =
    await env.DB.prepare(`
      INSERT INTO stories
      (
        user_id,
        content,
        media_url,
        media_type
      )
      VALUES (?, ?, ?, ?)
    `).bind(
      user.id,
      content,
      mediaUrl,
      mediaType
    ).run();

  const storyId =
    Number(result.meta?.last_row_id);

  return json({
    ok: true,
    story: {
      id: storyId,
      userId: user.id,
      content,
      text: content,
      mediaUrl,
      mediaType,
      createdAt: now()
    }
  }, 201);
}

// ============================================================

async function getStoryFeed(
  user,
  env
) {
  const result =
    await env.DB.prepare(`
      SELECT
        s.id,
        s.user_id,
        s.content,
        s.content AS text,
        s.media_url,
        s.media_type,
        s.created_at,

        u.username,
        u.display_name,
        u.avatar_url

      FROM stories s

      JOIN users u
        ON u.id = s.user_id

      WHERE
        datetime(s.created_at)
          >= datetime('now', '-24 hours')

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

async function createReel(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const mediaUrl =
    cleanText(
      body.mediaUrl !== undefined
        ? body.mediaUrl
        : body.videoUrl,
      1000
    );

  const caption =
    cleanText(
      body.caption,
      2000
    );

  if (!mediaUrl) {
    return json({
      error: "Video URL is required."
    }, 400);
  }

  const result =
    await env.DB.prepare(`
      INSERT INTO reels
      (
        user_id,
        caption,
        media_url
      )
      VALUES (?, ?, ?)
    `).bind(
      user.id,
      caption,
      mediaUrl
    ).run();

  const reelId =
    Number(result.meta?.last_row_id);

  return json({
    ok: true,
    reel: {
      id: reelId,
      userId: user.id,
      mediaUrl,
      videoUrl: mediaUrl,
      caption,
      createdAt: now()
    }
  }, 201);
}

// ============================================================

async function getReels(
  user,
  env
) {
  const result =
    await env.DB.prepare(`
      SELECT
        r.id,
        r.user_id,
        r.media_url,
        r.media_url AS video_url,
        r.caption,
        r.created_at,

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
    reels: result.results || []
  });
}

// ============================================================
// CHAT
// ============================================================

async function getChats(
  user,
  env
) {
  const result =
    await env.DB.prepare(`
      SELECT
        c.id,
        c.name,
        c.is_group,

        CASE
          WHEN c.is_group = 1
          THEN 'group'
          ELSE 'direct'
        END AS type,

        c.created_at

      FROM chats c

      JOIN chat_members cm
        ON cm.chat_id = c.id

      WHERE cm.user_id = ?

      ORDER BY c.created_at DESC
    `).bind(
      user.id
    ).all();

  return json({
    chats: result.results || []
  });
}

// ============================================================

async function createChat(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const targetUserId =
    parseId(body.userId);

  if (
    targetUserId === null ||
    targetUserId === Number(user.id)
  ) {
    return json({
      error: "Invalid target user."
    }, 400);
  }

  const target =
    await getUserById(
      targetUserId,
      env
    );

  if (!target) {
    return json({
      error: "User not found."
    }, 404);
  }

  // Check target's message privacy.
  const settings =
    await env.DB.prepare(`
      SELECT message_privacy
      FROM user_settings
      WHERE user_id = ?
      LIMIT 1
    `).bind(
      String(targetUserId)
    ).first();

  const privacy =
    settings?.message_privacy || "everyone";

  if (privacy === "nobody") {
    return json({
      error: "This user does not accept messages."
    }, 403);
  }

  if (privacy === "followers") {
    const follows =
      await env.DB.prepare(`
        SELECT 1
        FROM follows
        WHERE follower_id = ?
          AND following_id = ?
        LIMIT 1
      `).bind(
        targetUserId,
        user.id
      ).first();

    if (!follows) {
      return json({
        error: "This user only accepts messages from followers."
      }, 403);
    }
  }

  // Existing direct chat.
  const existing =
    await env.DB.prepare(`
      SELECT c.id
      FROM chats c

      JOIN chat_members a
        ON a.chat_id = c.id

      JOIN chat_members b
        ON b.chat_id = c.id

      WHERE
        c.is_group = 0
        AND a.user_id = ?
        AND b.user_id = ?

      LIMIT 1
    `).bind(
      user.id,
      targetUserId
    ).first();

  if (existing) {
    return json({
      ok: true,
      chatId: existing.id,
      existing: true
    });
  }

  const chatResult =
    await env.DB.prepare(`
      INSERT INTO chats
      (
        name,
        is_group
      )
      VALUES ('', 0)
    `).run();

  const chatId =
    Number(chatResult.meta?.last_row_id);

  try {
    await env.DB.batch([
      env.DB.prepare(`
        INSERT INTO chat_members
        (
          chat_id,
          user_id
        )
        VALUES (?, ?)
      `).bind(
        chatId,
        user.id
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
        targetUserId
      )
    ]);
  } catch (error) {
    await env.DB.prepare(`
      DELETE FROM chats
      WHERE id = ?
    `).bind(chatId).run();

    throw error;
  }

  return json({
    ok: true,
    chatId,
    existing: false
  }, 201);
}

// ============================================================

async function getMessages(
  chatId,
  user,
  env
) {
  if (
    !(await isChatMember(
      chatId,
      user.id,
      env
    ))
  ) {
    return json({
      error: "You are not a member of this chat."
    }, 403);
  }

  const result =
    await env.DB.prepare(`
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

      JOIN users u
        ON u.id = m.user_id

      WHERE m.chat_id = ?

      ORDER BY m.created_at ASC
      LIMIT 500
    `).bind(
      chatId
    ).all();

  return json({
    messages: result.results || []
  });
}

// ============================================================

async function sendMessage(
  chatId,
  request,
  user,
  env
) {
  if (
    !(await isChatMember(
      chatId,
      user.id,
      env
    ))
  ) {
    return json({
      error: "You are not a member of this chat."
    }, 403);
  }

  const body =
    await readJSON(request);

  const content =
    cleanText(
      body.content,
      5000
    );

  const mediaUrl =
    cleanText(
      body.mediaUrl,
      1000
    );

  if (!content && !mediaUrl) {
    return json({
      error: "Message cannot be empty."
    }, 400);
  }

  const result =
    await env.DB.prepare(`
      INSERT INTO messages
      (
        chat_id,
        user_id,
        content,
        media_url
      )
      VALUES (?, ?, ?, ?)
    `).bind(
      chatId,
      user.id,
      content,
      mediaUrl
    ).run();

  const messageId =
    Number(result.meta?.last_row_id);

  return json({
    ok: true,
    message: {
      id: messageId,
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

async function createGroup(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const name =
    cleanText(
      body.name,
      100
    );

  const members =
    Array.isArray(body.members)
      ? body.members
      : [];

  if (!name) {
    return json({
      error: "Group name is required."
    }, 400);
  }

  if (members.length > 49) {
    return json({
      error: "A group can contain at most 50 members."
    }, 400);
  }

  const memberIds =
    [
      Number(user.id),
      ...members.map(parseId)
    ]
      .filter(
        id =>
          id !== null &&
          Number.isSafeInteger(id) &&
          id > 0
      );

  const uniqueIds =
    [...new Set(memberIds)];

  if (uniqueIds.length < 2) {
    return json({
      error: "Add at least one other valid member."
    }, 400);
  }

  const placeholders =
    uniqueIds.map(() => "?").join(",");

  const validUsers =
    await env.DB.prepare(`
      SELECT id
      FROM users
      WHERE id IN (${placeholders})
    `).bind(
      ...uniqueIds
    ).all();

  const validIds =
    new Set(
      (validUsers.results || [])
        .map(row => Number(row.id))
    );

  if (
    !validIds.has(Number(user.id)) ||
    validIds.size !== uniqueIds.length
  ) {
    return json({
      error: "One or more group members do not exist."
    }, 400);
  }

  const chatResult =
    await env.DB.prepare(`
      INSERT INTO chats
      (
        name,
        is_group
      )
      VALUES (?, 1)
    `).bind(name).run();

  const chatId =
    Number(chatResult.meta?.last_row_id);

  const statements =
    [...validIds].map(memberId =>
      env.DB.prepare(`
        INSERT INTO chat_members
        (
          chat_id,
          user_id
        )
        VALUES (?, ?)
        ON CONFLICT(chat_id, user_id)
        DO NOTHING
      `).bind(
        chatId,
        memberId
      )
    );

  try {
    await env.DB.batch(statements);
  } catch (error) {
    await env.DB.prepare(`
      DELETE FROM chats
      WHERE id = ?
    `).bind(chatId).run();

    throw error;
  }

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
      user_id,
      actor_id,
      type,
      post_id
    )
    VALUES (?, ?, ?, ?)
  `).bind(
    userId,
    actorId,
    type,
    postId
  ).run();
}

// ============================================================

async function getNotifications(
  user,
  env
) {
  const result =
    await env.DB.prepare(`
      SELECT
        n.id,
        n.actor_id,
        n.type,
        n.post_id,
        n.is_read,
        n.created_at,

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
      user.id
    ).all();

  return json({
    notifications: result.results || []
  });
}

// ============================================================

async function markNotificationsRead(
  user,
  env
) {
  await env.DB.prepare(`
    UPDATE notifications
    SET is_read = 1
    WHERE user_id = ?
  `).bind(
    user.id
  ).run();

  return json({
    ok: true
  });
}

// ============================================================
// SETTINGS
// ============================================================

async function getSettings(
  user,
  env
) {
  const userId =
    String(user.id);

  const row =
    await env.DB.prepare(`
      SELECT
        theme,
        profile_visibility,
        message_privacy,
        notification_settings
      FROM user_settings
      WHERE user_id = ?
      LIMIT 1
    `).bind(userId).first();

  return json({
    settings: row || {
      theme: "system",
      profile_visibility: "public",
      message_privacy: "everyone",
      notification_settings: "{}"
    }
  });
}

// ============================================================

async function updateSettings(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const userId =
    String(user.id);

  const existing =
    await env.DB.prepare(`
      SELECT
        theme,
        profile_visibility,
        message_privacy,
        notification_settings
      FROM user_settings
      WHERE user_id = ?
      LIMIT 1
    `).bind(userId).first();

  const theme =
    ["light", "dark", "system"].includes(
      body.theme
    )
      ? body.theme
      : (existing?.theme || "system");

  const profileVisibility =
    [
      "public",
      "followers",
      "private"
    ].includes(body.profileVisibility)
      ? body.profileVisibility
      : (
        existing?.profile_visibility ||
        "public"
      );

  const messagePrivacy =
    [
      "everyone",
      "followers",
      "nobody"
    ].includes(body.messagePrivacy)
      ? body.messagePrivacy
      : (
        existing?.message_privacy ||
        "everyone"
      );

  let notificationSettings =
    existing?.notification_settings ||
    "{}";

  if (body.notifications !== undefined) {
    if (
      body.notifications === null ||
      typeof body.notifications !== "object" ||
      Array.isArray(body.notifications)
    ) {
      return json({
        error: "Invalid notification settings."
      }, 400);
    }

    notificationSettings =
      JSON.stringify(
        body.notifications
      );
  }

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
    userId,
    theme,
    profileVisibility,
    messagePrivacy,
    notificationSettings
  ).run();

  return json({
    ok: true
  });
}

// ============================================================
// SESSION AUTHENTICATION
// ============================================================

async function requireUser(
  request,
  env
) {
  const token =
    getCookie(
      request,
      SESSION_COOKIE
    );

  if (!token) {
    return null;
  }

  // IMPORTANT:
  // sessions.token stores the RAW random token.
  // It does NOT store a SHA-256 hash.

  const session =
    await env.DB.prepare(`
      SELECT
        user_id,
        expires_at
      FROM sessions
      WHERE token = ?
      LIMIT 1
    `).bind(token).first();

  if (!session) {
    return null;
  }

  if (
    Number(session.expires_at) < Date.now()
  ) {
    await env.DB.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `).bind(token).run();

    return null;
  }

  return getUserById(
    session.user_id,
    env
  );
}

// ============================================================

async function createSession(
  userId,
  env
) {
  const rawToken =
    randomToken(48);

  const expiresAt =
    Date.now() +
    SESSION_DAYS *
    24 *
    60 *
    60 *
    1000;

  // IMPORTANT:
  // Store RAW token because sessions.token is the
  // actual session token column.

  await env.DB.prepare(`
    INSERT INTO sessions
    (
      user_id,
      token,
      expires_at
    )
    VALUES (?, ?, ?)
  `).bind(
    userId,
    rawToken,
    expiresAt
  ).run();

  return rawToken;
}

// ============================================================
// PASSWORD HASHING
// ============================================================

async function hashPassword(
  password
) {
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

// ============================================================

async function verifyPassword(
  password,
  stored
) {
  try {
    if (
      typeof stored !== "string" ||
      !stored
    ) {
      return false;
    }

    const parts =
      stored.split("$");

    if (
      parts.length !== 4 ||
      parts[0] !== "pbkdf2"
    ) {
      return false;
    }

    const iterations =
      Number(parts[1]);

    if (
      !Number.isInteger(iterations) ||
      iterations < 1000 ||
      iterations > 1000000
    ) {
      return false;
    }

    const salt =
      base64ToBytes(parts[2]);

    const expected =
      base64ToBytes(parts[3]);

    if (
      salt.length === 0 ||
      expected.length !== 32
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

  } catch {
    return false;
  }
}

// ============================================================
// RESEND
// ============================================================

async function sendResetEmail(
  env,
  email,
  resetURL
) {
  try {
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
            from: env.RESET_FROM_EMAIL,

            to: [email],

            subject:
              "Reset your Zilnet password",

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

    if (!response.ok) {
      console.error(
        "Resend API failed:",
        response.status
      );
    }

  } catch (error) {
    console.error(
      "Failed to send reset email:",
      error
    );
  }
}

// ============================================================
// DATABASE HELPERS
// ============================================================

async function getUserById(
  id,
  env
) {
  const numId =
    parseId(id);

  if (numId === null) {
    return null;
  }

  return env.DB.prepare(`
    SELECT *
    FROM users
    WHERE id = ?
    LIMIT 1
  `).bind(numId).first();
}

// ============================================================

async function isChatMember(
  chatId,
  userId,
  env
) {
  const row =
    await env.DB.prepare(`
      SELECT 1
      FROM chat_members
      WHERE chat_id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      chatId,
      userId
    ).first();

  return !!row;
}

// ============================================================

async function count(
  db,
  sql,
  value
) {
  const row =
    await db
      .prepare(sql)
      .bind(value)
      .first();

  return Number(
    row?.n || 0
  );
}

// ============================================================
// UTILITIES
// ============================================================

function publicUser(user) {
  if (!user) {
    return null;
  }

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

// ============================================================

function parseSkills(value) {
  if (!value) {
    return [];
  }

  try {
    const parsed =
      JSON.parse(value);

    if (Array.isArray(parsed)) {
      return parsed;
    }
  } catch {
    // Fall through.
  }

  return String(value)
    .split(",")
    .map(x => x.trim())
    .filter(Boolean);
}

// ============================================================

function parseId(value) {
  const n =
    Number(value);

  if (
    !Number.isSafeInteger(n) ||
    n <= 0
  ) {
    return null;
  }

  return n;
}

// ============================================================

function cleanUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

// ============================================================

function cleanEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

// ============================================================

function cleanText(
  value,
  max
) {
  return String(value || "")
    .trim()
    .slice(0, max);
}

// ============================================================

async function readJSON(request) {
  let data;

  try {
    data =
      await request.json();
  } catch {
    throw new HttpError(
      400,
      "Invalid JSON payload."
    );
  }

  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data)
  ) {
    throw new HttpError(
      400,
      "Invalid JSON payload."
    );
  }

  return data;
}

// ============================================================

function now() {
  return new Date().toISOString();
}

// ============================================================

function randomToken(
  length = 32
) {
  const bytes =
    crypto.getRandomValues(
      new Uint8Array(length)
    );

  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// ============================================================

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

// ============================================================

function bytesToBase64(bytes) {
  let binary = "";

  for (
    const byte of bytes
  ) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

// ============================================================

function base64ToBytes(value) {
  const binary =
    atob(value);

  return Uint8Array.from(
    binary,
    char => char.charCodeAt(0)
  );
}

// ============================================================

function constantTimeEqual(
  a,
  b
) {
  if (
    a.length !== b.length
  ) {
    return false;
  }

  let result = 0;

  for (
    let i = 0;
    i < a.length;
    i++
  ) {
    result |=
      a[i] ^ b[i];
  }

  return result === 0;
}

// ============================================================

function getCookie(
  request,
  name
) {
  const cookie =
    request.headers.get("Cookie") || "";

  const parts =
    cookie.split(";");

  for (
    const part of parts
  ) {
    const [key, ...rest] =
      part.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

// ============================================================

function makeSessionCookie(
  token
) {
  return [
    `${SESSION_COOKIE}=${token}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${SESSION_DAYS * 24 * 60 * 60}`
  ].join("; ");
}

// ============================================================

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

// ============================================================

function withCookie(
  response,
  cookie
) {
  const headers =
    new Headers(
      response.headers
    );

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

// ============================================================

function json(
  data,
  status = 200
) {
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

// ============================================================

function getExtension(
  filename,
  type
) {
  const match =
    String(filename || "")
      .match(
        /\.([a-zA-Z0-9]+)$/
      );

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

// ============================================================

function escapeHTML(
  value
) {
  return String(value)
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );
}
