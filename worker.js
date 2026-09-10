// ============================================================
// ZILNET — CLOUDFLARE WORKER
// PART 1/3
// ============================================================

const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 100000;
const PASSWORD_KEY_LENGTH = 32;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const method = request.method;
      const path = url.pathname;

      // --------------------------------------------------------
      // CORS / OPTIONS
      // --------------------------------------------------------

      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders()
        });
      }

      // --------------------------------------------------------
      // API ROUTES
      // --------------------------------------------------------

      if (path.startsWith("/api/")) {

        // ---------- PUBLIC AUTH ----------

        if (path === "/api/signup" && method === "POST") {
          return await signup(request, env);
        }

        if (path === "/api/login" && method === "POST") {
          return await login(request, env);
        }

        if (path === "/api/logout" && method === "POST") {
          return await logout(request, env);
        }

        if (path === "/api/forgot-password" && method === "POST") {
          return await forgotPassword(request, env);
        }

        if (path === "/api/reset-password" && method === "POST") {
          return await resetPassword(request, env);
        }

        // ---------- AUTH REQUIRED ----------

        const user = await requireAuth(request, env);

        if (path === "/api/me" && method === "GET") {
          return json({
            user: privateUser(user)
          });
        }

        if (path === "/api/profile" && method === "GET") {
          return await getOwnProfile(user, env);
        }

        if (path === "/api/profile/update" && method === "POST") {
          return await updateProfile(request, user, env);
        }

        if (path.startsWith("/api/profile/") && method === "GET") {
          const username = decodeURIComponent(
            path.slice("/api/profile/".length)
          );

          if (!username) {
            throw new HttpError(400, "Username is required");
          }

          return await getPublicProfile(username, user, env);
        }

        if (path === "/api/search" && method === "GET") {
          return await searchUsers(request, env);
        }

        if (
          path.startsWith("/api/users/") &&
          path.endsWith("/follow") &&
          method === "POST"
        ) {
          const idText = path.slice(
            "/api/users/".length,
            -"/follow".length
          );

          const targetId = parsePositiveInt(idText);

          if (!targetId) {
            throw new HttpError(400, "Invalid user ID");
          }

          return await toggleFollow(targetId, user, env);
        }

        // ------------------------------------------------------
        // FEED
        // ------------------------------------------------------

        if (path === "/api/feed" && method === "GET") {
          return await getFeed(user, env);
        }

        // ------------------------------------------------------
        // POSTS
        // ------------------------------------------------------

        if (path === "/api/posts" && method === "POST") {
          return await createPost(request, user, env);
        }

        if (path === "/api/posts" && method === "GET") {
          return await getFeed(user, env);
        }

        const postMatch = path.match(/^\/api\/posts\/(\d+)$/);

        if (postMatch && method === "GET") {
          return await getPost(
            Number(postMatch[1]),
            user,
            env
          );
        }

        if (postMatch && method === "DELETE") {
          return await deletePost(
            Number(postMatch[1]),
            user,
            env
          );
        }

        const likeMatch = path.match(
          /^\/api\/posts\/(\d+)\/like$/
        );

        if (likeMatch && method === "POST") {
          return await toggleLike(
            Number(likeMatch[1]),
            user,
            env
          );
        }

        const commentMatch = path.match(
          /^\/api\/posts\/(\d+)\/comments$/
        );

        if (commentMatch && method === "GET") {
          return await getComments(
            Number(commentMatch[1]),
            env
          );
        }

        if (commentMatch && method === "POST") {
          return await createComment(
            request,
            Number(commentMatch[1]),
            user,
            env
          );
        }

        const saveMatch = path.match(
          /^\/api\/posts\/(\d+)\/save$/
        );

        if (saveMatch && method === "POST") {
          return await toggleSave(
            Number(saveMatch[1]),
            user,
            env
          );
        }

        // ------------------------------------------------------
        // MEDIA
        // ------------------------------------------------------

        if (path === "/api/upload" && method === "POST") {
          return await uploadMedia(request, user, env);
        }

        // ------------------------------------------------------
        // STORIES
        // ------------------------------------------------------

        if (path === "/api/stories/feed" && method === "GET") {
          return await getStoryFeed(user, env);
        }

        if (path === "/api/stories" && method === "POST") {
          return await createStory(request, user, env);
        }

        // ------------------------------------------------------
        // REELS
        // ------------------------------------------------------

        if (path === "/api/reels/feed" && method === "GET") {
          return await getReels(env);
        }

        if (path === "/api/reels" && method === "POST") {
          return await createReel(request, user, env);
        }

        // ------------------------------------------------------
        // CHATS
        // ------------------------------------------------------

        if (path === "/api/chats" && method === "GET") {
          return await getChats(user, env);
        }

        if (path === "/api/chats" && method === "POST") {
          return await createChat(request, user, env);
        }

        const messageMatch = path.match(
          /^\/api\/chats\/(\d+)\/messages$/
        );

        if (messageMatch && method === "GET") {
          return await getMessages(
            Number(messageMatch[1]),
            user,
            env
          );
        }

        if (messageMatch && method === "POST") {
          return await sendMessage(
            request,
            Number(messageMatch[1]),
            user,
            env
          );
        }

        // ------------------------------------------------------
        // GROUPS
        // ------------------------------------------------------

        if (path === "/api/groups" && method === "POST") {
          return await createGroup(request, user, env);
        }

        // ------------------------------------------------------
        // NOTIFICATIONS
        // ------------------------------------------------------

        if (path === "/api/notifications" && method === "GET") {
          return await getNotifications(user, env);
        }

        if (
          path === "/api/notifications/read" &&
          method === "POST"
        ) {
          return await markNotificationsRead(user, env);
        }

        // ------------------------------------------------------
        // SETTINGS
        // ------------------------------------------------------

        if (path === "/api/settings" && method === "GET") {
          return await getSettings(user, env);
        }

        if (path === "/api/settings" && method === "POST") {
          return await updateSettings(request, user, env);
        }

        throw new HttpError(404, "API route not found");
      }

      // --------------------------------------------------------
      // MEDIA FROM R2
      // --------------------------------------------------------

      if (path.startsWith("/media/") && env.MEDIA) {
        return await serveMedia(path, env);
      }

      // --------------------------------------------------------
      // STATIC WEBSITE
      // --------------------------------------------------------

      if (env.ASSETS) {
        return await env.ASSETS.fetch(request);
      }

      return new Response("Zilnet is running.", {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=utf-8"
        }
      });

    } catch (error) {
      return handleError(error);
    }
  }
};


// ============================================================
// AUTH
// ============================================================

async function signup(request, env) {
  const body = await readJSON(request);

  const username = cleanUsername(body.username);
  const email = cleanEmail(body.email);
  const password = String(body.password || "");

  if (!username) {
    throw new HttpError(400, "Username is required");
  }

  if (!/^[a-z0-9_.]{3,30}$/.test(username)) {
    throw new HttpError(
      400,
      "Username must be 3-30 characters and use letters, numbers, _ or ."
    );
  }

  if (!email) {
    throw new HttpError(400, "Valid email is required");
  }

  if (password.length < 8) {
    throw new HttpError(
      400,
      "Password must be at least 8 characters"
    );
  }

  const existing = await env.DB.prepare(
    `SELECT id FROM users
     WHERE username = ? OR email = ?
     LIMIT 1`
  )
    .bind(username, email)
    .first();

  if (existing) {
    throw new HttpError(
      409,
      "Username or email is already in use"
    );
  }

  const passwordHash = await hashPassword(password);

  const result = await env.DB.prepare(
    `INSERT INTO users
      (
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
     VALUES (?, ?, ?, '', '', '', ?, '', 0)`
  )
    .bind(
      username,
      email,
      username,
      passwordHash
    )
    .run();

  const userId = Number(result.meta.last_row_id);

  if (!userId) {
    throw new HttpError(
      500,
      "Could not create user"
    );
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO user_settings
      (
        user_id,
        theme,
        profile_visibility,
        message_privacy,
        notification_settings
      )
     VALUES (?, 'system', 'public', 'everyone', '{}')`
  )
    .bind(String(userId))
    .run();

  const user = await getUserById(userId, env);

  const token = await createSession(userId, env);

  return json(
    {
      user: privateUser(user),
      token
    },
    201,
    {
      "Set-Cookie": makeSessionCookie(token)
    }
  );
}


async function login(request, env) {
  const body = await readJSON(request);

  const identifier = String(
    body.username ??
    body.email ??
    body.identifier ??
    ""
  )
    .trim()
    .toLowerCase();

  const password = String(body.password || "");

  if (!identifier || !password) {
    throw new HttpError(
      400,
      "Username/email and password are required"
    );
  }

  const user = await env.DB.prepare(
    `SELECT *
     FROM users
     WHERE username = ? OR email = ?
     LIMIT 1`
  )
    .bind(identifier, identifier)
    .first();

  if (!user) {
    throw new HttpError(
      401,
      "Invalid username/email or password"
    );
  }

  const valid = await verifyPassword(
    password,
    user.password_hash
  );

  if (!valid) {
    throw new HttpError(
      401,
      "Invalid username/email or password"
    );
  }

  const token = await createSession(
    Number(user.id),
    env
  );

  return json(
    {
      user: privateUser(user),
      token
    },
    200,
    {
      "Set-Cookie": makeSessionCookie(token)
    }
  );
}


async function logout(request, env) {
  const token = getSessionToken(request);

  if (token) {
    await env.DB.prepare(
      `DELETE FROM sessions WHERE token = ?`
    )
      .bind(token)
      .run();
  }

  return json(
    { ok: true },
    200,
    {
      "Set-Cookie": clearSessionCookie()
    }
  );
}


// ============================================================
// SESSION
// ============================================================

async function createSession(userId, env) {
  const token = randomToken();

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 24 * 60 * 60;

  await env.DB.prepare(
    `INSERT INTO sessions
      (
        user_id,
        token,
        expires_at
      )
     VALUES (?, ?, ?)`
  )
    .bind(
      userId,
      token,
      expiresAt
    )
    .run();

  return token;
}


async function requireAuth(request, env) {
  const token = getSessionToken(request);

  if (!token) {
    throw new HttpError(
      401,
      "Authentication required"
    );
  }

  const session = await env.DB.prepare(
    `SELECT
       s.id AS session_id,
       s.user_id,
       s.token,
       s.expires_at,
       u.*
     FROM sessions s
     JOIN users u
       ON u.id = s.user_id
     WHERE s.token = ?
     LIMIT 1`
  )
    .bind(token)
    .first();

  if (!session) {
    throw new HttpError(
      401,
      "Invalid session"
    );
  }

  const now = Math.floor(Date.now() / 1000);

  if (Number(session.expires_at) <= now) {
    await env.DB.prepare(
      `DELETE FROM sessions WHERE id = ?`
    )
      .bind(session.session_id)
      .run();

    throw new HttpError(
      401,
      "Session expired"
    );
  }

  return session;
}


// ============================================================
// ME / PROFILES
// ============================================================

async function getOwnProfile(user, env) {
  const freshUser = await getUserById(
    Number(user.id),
    env
  );

  const settings = await env.DB.prepare(
    `SELECT
       user_id,
       theme,
       profile_visibility,
       message_privacy,
       notification_settings
     FROM user_settings
     WHERE user_id = ?
     LIMIT 1`
  )
    .bind(String(user.id))
    .first();

  return json({
    user: privateUser(freshUser),
    settings: settings || {
      user_id: String(user.id),
      theme: "system",
      profile_visibility: "public",
      message_privacy: "everyone",
      notification_settings: "{}"
    }
  });
}


async function updateProfile(request, user, env) {
  const body = await readJSON(request);

  const displayName =
    body.displayName !== undefined
      ? String(body.displayName).slice(0, 100)
      : null;

  const bio =
    body.bio !== undefined
      ? String(body.bio).slice(0, 1000)
      : null;

  const avatarUrl =
    body.avatarUrl !== undefined
      ? String(body.avatarUrl).slice(0, 2000)
      : null;

  const skills =
    body.skills !== undefined
      ? normalizeSkills(body.skills)
      : null;

  const fields = [];
  const values = [];

  if (displayName !== null) {
    fields.push("display_name = ?");
    values.push(displayName);
  }

  if (bio !== null) {
    fields.push("bio = ?");
    values.push(bio);
  }

  if (avatarUrl !== null) {
    fields.push("avatar_url = ?");
    values.push(avatarUrl);
  }

  if (skills !== null) {
    fields.push("skills = ?");
    values.push(skills);
  }

  if (!fields.length) {
    throw new HttpError(
      400,
      "Nothing to update"
    );
  }

  values.push(Number(user.id));

  await env.DB.prepare(
    `UPDATE users
     SET ${fields.join(", ")}
     WHERE id = ?`
  )
    .bind(...values)
    .run();

  const updated = await getUserById(
    Number(user.id),
    env
  );

  return json({
    user: privateUser(updated)
  });
}


async function getPublicProfile(
  username,
  viewer,
  env
) {
  const profile = await env.DB.prepare(
    `SELECT
       id,
       username,
       display_name,
       bio,
       avatar_url,
       skills,
       is_private,
       created_at
     FROM users
     WHERE username = ?
     LIMIT 1`
  )
    .bind(username.toLowerCase())
    .first();

  if (!profile) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const settings = await env.DB.prepare(
    `SELECT profile_visibility
     FROM user_settings
     WHERE user_id = ?
     LIMIT 1`
  )
    .bind(String(profile.id))
    .first();

  const visibility =
    settings?.profile_visibility ||
    (Number(profile.is_private) === 1
      ? "private"
      : "public");

  const isOwner =
    Number(profile.id) === Number(viewer.id);

  if (
    !isOwner &&
    visibility === "private"
  ) {
    return json({
      user: {
        id: profile.id,
        username: profile.username,
        display_name: profile.display_name,
        avatar_url: profile.avatar_url,
        is_private: 1
      },
      private: true
    });
  }

  const followerCount = await countRows(
    env.DB,
    `SELECT COUNT(*) AS count
     FROM follows
     WHERE following_id = ?`,
    profile.id
  );

  const followingCount = await countRows(
    env.DB,
    `SELECT COUNT(*) AS count
     FROM follows
     WHERE follower_id = ?`,
    profile.id
  );

  const postCount = await countRows(
    env.DB,
    `SELECT COUNT(*) AS count
     FROM posts
     WHERE user_id = ?`,
    profile.id
  );

  const following = await env.DB.prepare(
    `SELECT id
     FROM follows
     WHERE follower_id = ?
       AND following_id = ?
     LIMIT 1`
  )
    .bind(
      Number(viewer.id),
      Number(profile.id)
    )
    .first();

  return json({
    user: {
      id: profile.id,
      username: profile.username,
      display_name: profile.display_name,
      bio: profile.bio,
      avatar_url: profile.avatar_url,
      skills: profile.skills,
      is_private: Number(profile.is_private || 0),
      created_at: profile.created_at
    },
    stats: {
      followers: followerCount,
      following: followingCount,
      posts: postCount
    },
    is_following: !!following,
    private: false
  });
}


// ============================================================
// USER SEARCH
// ============================================================

async function searchUsers(request, env) {
  const url = new URL(request.url);

  const q = String(
    url.searchParams.get("q") || ""
  )
    .trim()
    .toLowerCase()
    .slice(0, 100);

  if (!q) {
    return json({
      users: []
    });
  }

  const search = `%${q}%`;

  const result = await env.DB.prepare(
    `SELECT
       id,
       username,
       display_name,
       bio,
       avatar_url,
       skills,
       is_private
     FROM users
     WHERE
       LOWER(username) LIKE ?
       OR LOWER(display_name) LIKE ?
       OR LOWER(skills) LIKE ?
     ORDER BY username ASC
     LIMIT 50`
  )
    .bind(
      search,
      search,
      search
    )
    .all();

  return json({
    users: result.results || []
  });
}


// ============================================================
// FOLLOW SYSTEM
// ============================================================

async function toggleFollow(
  targetId,
  user,
  env
) {
  if (
    Number(targetId) === Number(user.id)
  ) {
    throw new HttpError(
      400,
      "You cannot follow yourself"
    );
  }

  const target = await getUserById(
    targetId,
    env
  );

  if (!target) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const existing = await env.DB.prepare(
    `SELECT id
     FROM follows
     WHERE follower_id = ?
       AND following_id = ?
     LIMIT 1`
  )
    .bind(
      Number(user.id),
      targetId
    )
    .first();

  if (existing) {
    await env.DB.prepare(
      `DELETE FROM follows
       WHERE follower_id = ?
         AND following_id = ?`
    )
      .bind(
        Number(user.id),
        targetId
      )
      .run();

    return json({
      following: false
    });
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO follows
      (
        follower_id,
        following_id
      )
     VALUES (?, ?)`
  )
    .bind(
      Number(user.id),
      targetId
    )
    .run();

  await createNotification(
    env,
    targetId,
    Number(user.id),
    "follow",
    null
  );

  return json({
    following: true
  });
}


// ============================================================
// PASSWORD RESET
// ============================================================

async function forgotPassword(request, env) {
  const body = await readJSON(request);

  const email = cleanEmail(body.email);

  // Always return the same response so the endpoint
  // does not reveal whether an account exists.
  if (!email) {
    return json({
      ok: true,
      message:
        "If an account exists, a reset email will be sent."
    });
  }

  const user = await env.DB.prepare(
    `SELECT id, username, email
     FROM users
     WHERE email = ?
     LIMIT 1`
  )
    .bind(email)
    .first();

  if (!user) {
    return json({
      ok: true,
      message:
        "If an account exists, a reset email will be sent."
    });
  }

  const resetId = crypto.randomUUID();
  const rawToken = randomToken();
  const tokenHash = await sha256(rawToken);

  const expiresAt =
    Math.floor(Date.now() / 1000) +
    15 * 60;

  await env.DB.prepare(
    `DELETE FROM password_resets
     WHERE user_id = ?`
  )
    .bind(String(user.id))
    .run();

  await env.DB.prepare(
    `INSERT INTO password_resets
      (
        id,
        user_id,
        token_hash,
        expires_at,
        created_at
      )
     VALUES (?, ?, ?, ?, ?)`
  )
    .bind(
      resetId,
      String(user.id),
      tokenHash,
      expiresAt,
      new Date().toISOString()
    )
    .run();

  // Send the email only if RESEND_API_KEY exists.
  if (
    env.RESEND_API_KEY &&
    user.email
  ) {
    const resetUrl =
      `${getOrigin(request)}/reset-password` +
      `?token=${encodeURIComponent(rawToken)}`;

    await sendResetEmail(
      env,
      user.email,
      resetUrl
    );
  }

  return json({
    ok: true,
    message:
      "If an account exists, a reset email will be sent."
  });
}


async function resetPassword(request, env) {
  const body = await readJSON(request);

  const token = String(
    body.token || ""
  );

  const password = String(
    body.password || ""
  );

  if (!token) {
    throw new HttpError(
      400,
      "Reset token is required"
    );
  }

  if (password.length < 8) {
    throw new HttpError(
      400,
      "Password must be at least 8 characters"
    );
  }

  const tokenHash = await sha256(token);

  const reset = await env.DB.prepare(
    `SELECT
       id,
       user_id,
       expires_at
     FROM password_resets
     WHERE token_hash = ?
     LIMIT 1`
  )
    .bind(tokenHash)
    .first();

  if (!reset) {
    throw new HttpError(
      400,
      "Invalid or expired reset token"
    );
  }

  const now = Math.floor(Date.now() / 1000);

  if (Number(reset.expires_at) <= now) {
    await env.DB.prepare(
      `DELETE FROM password_resets
       WHERE id = ?`
    )
      .bind(reset.id)
      .run();

    throw new HttpError(
      400,
      "Invalid or expired reset token"
    );
  }

  const passwordHash =
    await hashPassword(password);

  await env.DB.prepare(
    `UPDATE users
     SET password_hash = ?,
         password_salt = ''
     WHERE id = ?`
  )
    .bind(
      passwordHash,
      Number(reset.user_id)
    )
    .run();

  // Invalidate all existing sessions after
  // a successful password reset.
  await env.DB.prepare(
    `DELETE FROM sessions
     WHERE user_id = ?`
  )
    .bind(Number(reset.user_id))
    .run();

  await env.DB.prepare(
    `DELETE FROM password_resets
     WHERE id = ?`
  )
    .bind(reset.id)
    .run();

  return json({
    ok: true,
    message: "Password reset successfully"
  });
}


// ============================================================
// PASSWORD HASHING — PBKDF2
// ============================================================

async function hashPassword(password) {
  const salt = crypto.getRandomValues(
    new Uint8Array(16)
  );

  const keyMaterial =
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
        salt,
        iterations: PASSWORD_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      PASSWORD_KEY_LENGTH * 8
    );

  return [
    "pbkdf2",
    "sha256",
    PASSWORD_ITERATIONS,
    bytesToBase64(salt),
    bytesToBase64(new Uint8Array(bits))
  ].join("$");
}


async function verifyPassword(
  password,
  stored
) {
  if (
    typeof stored !== "string"
  ) {
    return false;
  }

  const parts = stored.split("$");

  if (
    parts.length !== 5 ||
    parts[0] !== "pbkdf2" ||
    parts[1] !== "sha256"
  ) {
    return false;
  }

  const iterations =
    Number(parts[2]);

  if (
    !Number.isInteger(iterations) ||
    iterations < 10000 ||
    iterations > 1000000
  ) {
    return false;
  }

  let salt;
  let expected;

  try {
    salt = base64ToBytes(parts[3]);
    expected = base64ToBytes(parts[4]);
  } catch {
    return false;
  }

  if (
    salt.length < 8 ||
    expected.length === 0
  ) {
    return false;
  }

  const keyMaterial =
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
        salt,
        iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      expected.length * 8
    );

  return timingSafeEqual(
    new Uint8Array(bits),
    expected
  );
}


// ============================================================
// EMAIL
// ============================================================

async function sendResetEmail(
  env,
  email,
  resetUrl
) {
  const response = await fetch(
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
          env.RESEND_FROM ||
          "Zilnet <onboarding@resend.dev>",
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
              <a href="${escapeHtml(resetUrl)}">
                Reset your password
              </a>
            </p>
            <p>
              This link expires in 15 minutes.
            </p>
          </div>
        `
      })
    }
  );

  if (!response.ok) {
    console.error(
      "Resend email failed:",
      await response.text()
    );
  }
}


// ============================================================
// BASIC USER HELPERS
// ============================================================

async function getUserById(
  userId,
  env
) {
  return await env.DB.prepare(
    `SELECT *
     FROM users
     WHERE id = ?
     LIMIT 1`
  )
    .bind(Number(userId))
    .first();
}


function privateUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: Number(user.id),
    username: user.username,
    email: user.email || "",
    display_name:
      user.display_name || "",
    bio:
      user.bio || "",
    avatar_url:
      user.avatar_url || "",
    skills:
      user.skills || "",
    is_private:
      Number(user.is_private || 0),
    created_at:
      user.created_at || null
  };
}


function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: Number(user.id),
    username: user.username,
    display_name:
      user.display_name || "",
    bio:
      user.bio || "",
    avatar_url:
      user.avatar_url || "",
    skills:
      user.skills || "",
    is_private:
      Number(user.is_private || 0),
    created_at:
      user.created_at || null
  };
}


function cleanUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}


function cleanEmail(value) {
  const email = String(value || "")
    .trim()
    .toLowerCase();

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return "";
  }

  return email;
}


function normalizeSkills(value) {
  if (Array.isArray(value)) {
    return value
      .map(x => String(x).trim())
      .filter(Boolean)
      .slice(0, 30)
      .join(", ");
  }

  return String(value || "")
    .slice(0, 1000);
}
