// ============================================================
// ZILNET — CLOUDFLARE WORKER
// COMPLETE EDITED VERSION
// ============================================================

const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 100000;
const PASSWORD_KEY_LENGTH = 32;


// ============================================================
// MAIN WORKER
// ============================================================

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const method = request.method;
      const path = url.pathname;

      // --------------------------------------------------------
      // OPTIONS
      // --------------------------------------------------------

      if (method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders()
        });
      }

      // --------------------------------------------------------
      // API
      // --------------------------------------------------------

      if (path.startsWith("/api/")) {

        // ======================================================
        // PUBLIC AUTH
        // ======================================================

        if (path === "/api/signup" && method === "POST") {
          return await signup(request, env);
        }

        if (path === "/api/login" && method === "POST") {
          return await login(request, env);
        }

        if (path === "/api/logout" && method === "POST") {
          return await logout(request, env);
        }

        if (
          path === "/api/forgot-password" &&
          method === "POST"
        ) {
          return await forgotPassword(request, env);
        }

        if (
          path === "/api/reset-password" &&
          method === "POST"
        ) {
          return await resetPassword(request, env);
        }

        // ------------------------------------------------------
        // PUBLIC PROFILE LOOKUP
        // ------------------------------------------------------
        // These are intentionally allowed without authentication
        // because profiles are designed to be publicly visible.

        if (
          path.startsWith("/api/profile/") &&
          method === "GET"
        ) {
          const username = decodeURIComponent(
            path.slice("/api/profile/".length)
          );

          if (!username) {
            throw new HttpError(
              400,
              "Username is required"
            );
          }

          const viewer = await optionalAuth(
            request,
            env
          );

          return await getPublicProfile(
            username,
            viewer,
            env
          );
        }

        // Compatibility:
        // /api/users/:username
        if (
          path.startsWith("/api/users/") &&
          method === "GET" &&
          !path.endsWith("/follow")
        ) {
          const username = decodeURIComponent(
            path.slice("/api/users/".length)
          );

          if (!username) {
            throw new HttpError(
              400,
              "Username is required"
            );
          }

          const viewer = await optionalAuth(
            request,
            env
          );

          return await getPublicProfile(
            username,
            viewer,
            env
          );
        }

        // ======================================================
        // AUTH REQUIRED
        // ======================================================

        const user = await requireAuth(
          request,
          env
        );

        // ======================================================
        // ME
        // ======================================================

        if (
          path === "/api/me" &&
          method === "GET"
        ) {
          return json({
            user: privateUser(user)
          });
        }

        // ======================================================
        // OWN PROFILE
        // ======================================================

        if (
          path === "/api/profile" &&
          method === "GET"
        ) {
          return await getOwnProfile(
            user,
            env
          );
        }

        if (
          path === "/api/profile/update" &&
          method === "POST"
        ) {
          return await updateProfile(
            request,
            user,
            env
          );
        }

        // Compatibility with older frontend
        if (
          path === "/api/me" &&
          method === "PUT"
        ) {
          return await updateProfile(
            request,
            user,
            env
          );
        }

        // ======================================================
        // SEARCH
        // ======================================================

        if (
          path === "/api/search" &&
          method === "GET"
        ) {
          return await searchUsers(
            request,
            env
          );
        }

        // ======================================================
        // SUGGESTIONS
        // ======================================================

        if (
          path === "/api/suggestions" &&
          method === "GET"
        ) {
          return await getSuggestions(
            user,
            env
          );
        }

        // ======================================================
        // FOLLOW
        // ======================================================

        if (
          path.startsWith("/api/users/") &&
          path.endsWith("/follow") &&
          method === "POST"
        ) {
          const idText = path.slice(
            "/api/users/".length,
            -"/follow".length
          );

          const targetId =
            parsePositiveInt(idText);

          if (!targetId) {
            throw new HttpError(
              400,
              "Invalid user ID"
            );
          }

          return await toggleFollow(
            targetId,
            user,
            env
          );
        }

        // ======================================================
        // FOLLOWERS / FOLLOWING
        // ======================================================

        const followersMatch =
          path.match(
            /^\/api\/profile\/(\d+)\/followers$/
          );

        if (
          followersMatch &&
          method === "GET"
        ) {
          return await getFollowers(
            Number(followersMatch[1]),
            env
          );
        }

        const followingMatch =
          path.match(
            /^\/api\/profile\/(\d+)\/following$/
          );

        if (
          followingMatch &&
          method === "GET"
        ) {
          return await getFollowing(
            Number(followingMatch[1]),
            env
          );
        }

        // ======================================================
        // FEED
        // ======================================================

        if (
          path === "/api/feed" &&
          method === "GET"
        ) {
          return await getFeed(
            user,
            env
          );
        }

        // ======================================================
        // POSTS
        // ======================================================

        if (
          path === "/api/posts" &&
          method === "POST"
        ) {
          return await createPost(
            request,
            user,
            env
          );
        }

        if (
          path === "/api/posts" &&
          method === "GET"
        ) {
          return await getFeed(
            user,
            env
          );
        }

        const postMatch =
          path.match(
            /^\/api\/posts\/(\d+)$/
          );

        if (
          postMatch &&
          method === "GET"
        ) {
          return await getPost(
            Number(postMatch[1]),
            user,
            env
          );
        }

        if (
          postMatch &&
          method === "DELETE"
        ) {
          return await deletePost(
            Number(postMatch[1]),
            user,
            env
          );
        }

        const likeMatch =
          path.match(
            /^\/api\/posts\/(\d+)\/like$/
          );

        if (
          likeMatch &&
          method === "POST"
        ) {
          return await toggleLike(
            Number(likeMatch[1]),
            user,
            env
          );
        }

        const commentMatch =
          path.match(
            /^\/api\/posts\/(\d+)\/comments$/
          );

        if (
          commentMatch &&
          method === "GET"
        ) {
          return await getComments(
            Number(commentMatch[1]),
            env
          );
        }

        if (
          commentMatch &&
          method === "POST"
        ) {
          return await createComment(
            request,
            Number(commentMatch[1]),
            user,
            env
          );
        }

        const saveMatch =
          path.match(
            /^\/api\/posts\/(\d+)\/save$/
          );

        if (
          saveMatch &&
          method === "POST"
        ) {
          return await toggleSave(
            Number(saveMatch[1]),
            user,
            env
          );
        }

        // ======================================================
        // MEDIA
        // ======================================================

        if (
          path === "/api/upload" &&
          method === "POST"
        ) {
          return await uploadMedia(
            request,
            user,
            env
          );
        }

        // ======================================================
        // STORIES
        // ======================================================

        if (
          path === "/api/stories/feed" &&
          method === "GET"
        ) {
          return await getStoryFeed(
            user,
            env
          );
        }

        if (
          path === "/api/stories" &&
          method === "POST"
        ) {
          return await createStory(
            request,
            user,
            env
          );
        }

        // ======================================================
        // REELS
        // ======================================================

        if (
          path === "/api/reels/feed" &&
          method === "GET"
        ) {
          return await getReels(
            env
          );
        }

        if (
          path === "/api/reels" &&
          method === "POST"
        ) {
          return await createReel(
            request,
            user,
            env
          );
        }

        // ======================================================
        // CHATS
        // ======================================================

        if (
          path === "/api/chats" &&
          method === "GET"
        ) {
          return await getChats(
            user,
            env
          );
        }

        if (
          path === "/api/chats" &&
          method === "POST"
        ) {
          return await createChat(
            request,
            user,
            env
          );
        }

        // Compatibility:
        // GET /api/chats/:id
        const singleChatMatch =
          path.match(
            /^\/api\/chats\/(\d+)$/
          );

        if (
          singleChatMatch &&
          method === "GET"
        ) {
          return await getChat(
            Number(singleChatMatch[1]),
            user,
            env
          );
        }

        const messageMatch =
          path.match(
            /^\/api\/chats\/(\d+)\/messages$/
          );

        if (
          messageMatch &&
          method === "GET"
        ) {
          return await getMessages(
            Number(messageMatch[1]),
            user,
            env
          );
        }

        if (
          messageMatch &&
          method === "POST"
        ) {
          return await sendMessage(
            request,
            Number(messageMatch[1]),
            user,
            env
          );
        }

        // ======================================================
        // GROUPS
        // ======================================================

        if (
          path === "/api/groups" &&
          method === "POST"
        ) {
          return await createGroup(
            request,
            user,
            env
          );
        }

        // ======================================================
        // NOTIFICATIONS
        // ======================================================

        if (
          path === "/api/notifications" &&
          method === "GET"
        ) {
          return await getNotifications(
            user,
            env
          );
        }

        if (
          path === "/api/notifications/read" &&
          method === "POST"
        ) {
          return await markNotificationsRead(
            user,
            env
          );
        }

        // ======================================================
        // SETTINGS
        // ======================================================

        if (
          path === "/api/settings" &&
          method === "GET"
        ) {
          return await getSettings(
            user,
            env
          );
        }

        if (
          path === "/api/settings" &&
          method === "POST"
        ) {
          return await updateSettings(
            request,
            user,
            env
          );
        }

        throw new HttpError(
          404,
          "API route not found"
        );
      }

      // ========================================================
      // R2 MEDIA
      // ========================================================

      if (
        path.startsWith("/media/") &&
        env.MEDIA
      ) {
        return await serveMedia(
          path,
          env
        );
      }

      // ========================================================
      // STATIC WEBSITE
      // ========================================================

      if (env.ASSETS) {
        return await env.ASSETS.fetch(
          request
        );
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

    } catch (error) {
      return handleError(error);
    }
  }
};


// ============================================================
// AUTH
// ============================================================

async function signup(
  request,
  env
) {
  const body =
    await readJSON(request);

  const username =
    cleanUsername(body.username);

  const email =
    cleanEmail(body.email);

  const password =
    String(body.password || "");

  if (!username) {
    throw new HttpError(
      400,
      "Username is required"
    );
  }

  if (
    !/^[a-z0-9_.]{3,30}$/.test(username)
  ) {
    throw new HttpError(
      400,
      "Username must be 3-30 characters and use letters, numbers, _ or ."
    );
  }

  if (!email) {
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

  const existing =
    await env.DB.prepare(
      `SELECT id
       FROM users
       WHERE username = ?
          OR email = ?
       LIMIT 1`
    )
      .bind(
        username,
        email
      )
      .first();

  if (existing) {
    throw new HttpError(
      409,
      "Username or email is already in use"
    );
  }

  const passwordHash =
    await hashPassword(password);

  const result =
    await env.DB.prepare(
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

  const userId =
    Number(result.meta.last_row_id);

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
     VALUES (
       ?,
       'system',
       'public',
       'everyone',
       '{}'
     )`
  )
    .bind(String(userId))
    .run();

  const user =
    await getUserById(
      userId,
      env
    );

  const token =
    await createSession(
      userId,
      env
    );

  return json(
    {
      user: privateUser(user),
      token
    },
    201,
    {
      "Set-Cookie":
        makeSessionCookie(token)
    }
  );
}


async function login(
  request,
  env
) {
  const body =
    await readJSON(request);

  const identifier =
    String(
      body.username ??
      body.email ??
      body.identifier ??
      ""
    )
      .trim()
      .toLowerCase();

  const password =
    String(body.password || "");

  if (
    !identifier ||
    !password
  ) {
    throw new HttpError(
      400,
      "Username/email and password are required"
    );
  }

  const user =
    await env.DB.prepare(
      `SELECT *
       FROM users
       WHERE username = ?
          OR email = ?
       LIMIT 1`
    )
      .bind(
        identifier,
        identifier
      )
      .first();

  if (!user) {
    throw new HttpError(
      401,
      "Invalid username/email or password"
    );
  }

  const valid =
    await verifyPassword(
      password,
      user.password_hash
    );

  if (!valid) {
    throw new HttpError(
      401,
      "Invalid username/email or password"
    );
  }

  const token =
    await createSession(
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
      "Set-Cookie":
        makeSessionCookie(token)
    }
  );
}


async function logout(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (token) {
    await env.DB.prepare(
      `DELETE FROM sessions
       WHERE token = ?`
    )
      .bind(token)
      .run();
  }

  return json(
    {
      ok: true
    },
    200,
    {
      "Set-Cookie":
        clearSessionCookie()
    }
  );
}


// ============================================================
// SESSION
// ============================================================

async function createSession(
  userId,
  env
) {
  const token =
    randomToken();

  const expiresAt =
    Math.floor(
      Date.now() / 1000
    ) +
    SESSION_DAYS *
    24 *
    60 *
    60;

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
      Number(userId),
      token,
      expiresAt
    )
    .run();

  return token;
}


async function requireAuth(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (!token) {
    throw new HttpError(
      401,
      "Authentication required"
    );
  }

  const session =
    await env.DB.prepare(
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

  const now =
    Math.floor(
      Date.now() / 1000
    );

  if (
    Number(session.expires_at) <= now
  ) {
    await env.DB.prepare(
      `DELETE FROM sessions
       WHERE id = ?`
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


async function optionalAuth(
  request,
  env
) {
  const token =
    getSessionToken(request);

  if (!token) {
    return null;
  }

  const session =
    await env.DB.prepare(
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
    return null;
  }

  const now =
    Math.floor(
      Date.now() / 1000
    );

  if (
    Number(session.expires_at) <= now
  ) {
    await env.DB.prepare(
      `DELETE FROM sessions
       WHERE id = ?`
    )
      .bind(session.session_id)
      .run();

    return null;
  }

  return session;
}


// ============================================================
// PROFILE
// ============================================================

async function getOwnProfile(
  user,
  env
) {
  const freshUser =
    await getUserById(
      Number(user.id),
      env
    );

  let settings =
    await env.DB.prepare(
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

  if (!settings) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO user_settings
        (
          user_id,
          theme,
          profile_visibility,
          message_privacy,
          notification_settings
        )
       VALUES (
         ?,
         'system',
         'public',
         'everyone',
         '{}'
       )`
    )
      .bind(String(user.id))
      .run();

    settings =
      await env.DB.prepare(
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
  }

  return json({
    user:
      privateUser(freshUser),

    settings
  });
}


async function updateProfile(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const displayName =
    body.displayName !== undefined
      ? String(body.displayName)
          .slice(0, 100)
      : null;

  const bio =
    body.bio !== undefined
      ? String(body.bio)
          .slice(0, 1000)
      : null;

  const avatarUrl =
    body.avatarUrl !== undefined
      ? String(body.avatarUrl)
          .slice(0, 2000)
      : (
          body.avatar_url !== undefined
            ? String(body.avatar_url)
                .slice(0, 2000)
            : null
        );

  const skills =
    body.skills !== undefined
      ? normalizeSkills(body.skills)
      : null;

  const fields = [];
  const values = [];

  if (displayName !== null) {
    fields.push(
      "display_name = ?"
    );
    values.push(displayName);
  }

  if (bio !== null) {
    fields.push(
      "bio = ?"
    );
    values.push(bio);
  }

  if (avatarUrl !== null) {
    fields.push(
      "avatar_url = ?"
    );
    values.push(avatarUrl);
  }

  if (skills !== null) {
    fields.push(
      "skills = ?"
    );
    values.push(skills);
  }

  if (!fields.length) {
    throw new HttpError(
      400,
      "Nothing to update"
    );
  }

  values.push(
    Number(user.id)
  );

  await env.DB.prepare(
    `UPDATE users
     SET ${fields.join(", ")}
     WHERE id = ?`
  )
    .bind(...values)
    .run();

  const updated =
    await getUserById(
      Number(user.id),
      env
    );

  return json({
    user:
      privateUser(updated)
  });
}


async function getPublicProfile(
  username,
  viewer,
  env
) {
  const profile =
    await env.DB.prepare(
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
      .bind(
        username.toLowerCase()
      )
      .first();

  if (!profile) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const settings =
    await env.DB.prepare(
      `SELECT
         profile_visibility
       FROM user_settings
       WHERE user_id = ?
       LIMIT 1`
    )
      .bind(
        String(profile.id)
      )
      .first();

  const visibility =
    settings?.profile_visibility ||
    (
      Number(profile.is_private) === 1
        ? "private"
        : "public"
    );

  const viewerId =
    viewer
      ? Number(viewer.id)
      : null;

  const isOwner =
    viewerId === Number(profile.id);

  if (
    !isOwner &&
    visibility === "private"
  ) {
    return json({
      user: {
        id:
          Number(profile.id),

        username:
          profile.username,

        display_name:
          profile.display_name || "",

        avatar_url:
          profile.avatar_url || "",

        is_private: 1
      },

      private: true
    });
  }

  const followerCount =
    await countRows(
      env.DB,
      `SELECT COUNT(*) AS count
       FROM follows
       WHERE following_id = ?`,
      Number(profile.id)
    );

  const followingCount =
    await countRows(
      env.DB,
      `SELECT COUNT(*) AS count
       FROM follows
       WHERE follower_id = ?`,
      Number(profile.id)
    );

  const postCount =
    await countRows(
      env.DB,
      `SELECT COUNT(*) AS count
       FROM posts
       WHERE user_id = ?`,
      Number(profile.id)
    );

  let following = false;

  if (viewerId) {
    const row =
      await env.DB.prepare(
        `SELECT id
         FROM follows
         WHERE follower_id = ?
           AND following_id = ?
         LIMIT 1`
      )
        .bind(
          viewerId,
          Number(profile.id)
        )
        .first();

    following = !!row;
  }

  return json({
    user: {
      id:
        Number(profile.id),

      username:
        profile.username,

      display_name:
        profile.display_name || "",

      bio:
        profile.bio || "",

      avatar_url:
        profile.avatar_url || "",

      skills:
        profile.skills || "",

      is_private:
        Number(profile.is_private || 0),

      created_at:
        profile.created_at || null
    },

    stats: {
      followers:
        followerCount,

      following:
        followingCount,

      posts:
        postCount
    },

    is_following:
      following,

    private: false
  });
}


// ============================================================
// SEARCH
// ============================================================

async function searchUsers(
  request,
  env
) {
  const url =
    new URL(request.url);

  const q =
    String(
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

  const search =
    `%${q}%`;

  const result =
    await env.DB.prepare(
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
    users:
      result.results || []
  });
}


// ============================================================
// SUGGESTIONS
// ============================================================

async function getSuggestions(
  user,
  env
) {
  const result =
    await env.DB.prepare(
      `SELECT
         u.id,
         u.username,
         u.display_name,
         u.bio,
         u.avatar_url,
         u.skills,
         u.is_private
       FROM users u
       WHERE u.id != ?
         AND u.id NOT IN (
           SELECT following_id
           FROM follows
           WHERE follower_id = ?
         )
       ORDER BY u.id DESC
       LIMIT 20`
    )
      .bind(
        Number(user.id),
        Number(user.id)
      )
      .all();

  return json({
    users:
      result.results || []
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
  const followerId =
    Number(user.id);

  if (
    Number(targetId) === followerId
  ) {
    throw new HttpError(
      400,
      "You cannot follow yourself"
    );
  }

  const target =
    await getUserById(
      targetId,
      env
    );

  if (!target) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  const existing =
    await env.DB.prepare(
      `SELECT id
       FROM follows
       WHERE follower_id = ?
         AND following_id = ?
       LIMIT 1`
    )
      .bind(
        followerId,
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
        followerId,
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
      followerId,
      targetId
    )
    .run();

  await createNotification(
    env,
    targetId,
    followerId,
    "follow",
    null
  );

  return json({
    following: true
  });
}


// ============================================================
// FOLLOWERS
// ============================================================

async function getFollowers(
  userId,
  env
) {
  const result =
    await env.DB.prepare(
      `SELECT
         u.id,
         u.username,
         u.display_name,
         u.bio,
         u.avatar_url,
         u.skills,
         u.is_private
       FROM follows f
       JOIN users u
         ON u.id = f.follower_id
       WHERE f.following_id = ?
       ORDER BY u.username ASC
       LIMIT 500`
    )
      .bind(userId)
      .all();

  return json({
    users:
      result.results || []
  });
}


// ============================================================
// FOLLOWING
// ============================================================

async function getFollowing(
  userId,
  env
) {
  const result =
    await env.DB.prepare(
      `SELECT
         u.id,
         u.username,
         u.display_name,
         u.bio,
         u.avatar_url,
         u.skills,
         u.is_private
       FROM follows f
       JOIN users u
         ON u.id = f.following_id
       WHERE f.follower_id = ?
       ORDER BY u.username ASC
       LIMIT 500`
    )
      .bind(userId)
      .all();

  return json({
    users:
      result.results || []
  });
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
    cleanEmail(body.email);

  if (!email) {
    return json({
      ok: true,
      message:
        "If an account exists, a reset email will be sent."
    });
  }

  const user =
    await env.DB.prepare(
      `SELECT
         id,
         username,
         email
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

  const resetId =
    crypto.randomUUID();

  const rawToken =
    randomToken();

  const tokenHash =
    await sha256(rawToken);

  const expiresAt =
    Math.floor(
      Date.now() / 1000
    ) +
    15 * 60;

  await env.DB.prepare(
    `DELETE FROM password_resets
     WHERE user_id = ?`
  )
    .bind(
      String(user.id)
    )
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


async function resetPassword(
  request,
  env
) {
  const body =
    await readJSON(request);

  const token =
    String(body.token || "");

  const password =
    String(body.password || "");

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

  const tokenHash =
    await sha256(token);

  const reset =
    await env.DB.prepare(
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

  const now =
    Math.floor(
      Date.now() / 1000
    );

  if (
    Number(reset.expires_at) <= now
  ) {
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

  await env.DB.prepare(
    `DELETE FROM sessions
     WHERE user_id = ?`
  )
    .bind(
      Number(reset.user_id)
    )
    .run();

  await env.DB.prepare(
    `DELETE FROM password_resets
     WHERE id = ?`
  )
    .bind(reset.id)
    .run();

  return json({
    ok: true,
    message:
      "Password reset successfully"
  });
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
        iterations:
          PASSWORD_ITERATIONS,
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
    bytesToBase64(
      new Uint8Array(bits)
    )
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

  const parts =
    stored.split("$");

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
    salt =
      base64ToBytes(parts[3]);

    expected =
      base64ToBytes(parts[4]);
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

        body:
          JSON.stringify({
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
// USER HELPERS
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
    id:
      Number(user.id),

    username:
      user.username,

    email:
      user.email || "",

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
    id:
      Number(user.id),

    username:
      user.username,

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
  const email =
    String(value || "")
      .trim()
      .toLowerCase();

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
      email
    )
  ) {
    return "";
  }

  return email;
}


function normalizeSkills(value) {
  if (Array.isArray(value)) {
    return value
      .map(
        x => String(x).trim()
      )
      .filter(Boolean)
      .slice(0, 30)
      .join(", ");
  }

  return String(value || "")
    .slice(0, 1000);
}


// ============================================================
// FEED
// ============================================================

async function getFeed(
  user,
  env
) {
  const userId =
    Number(user.id);

  const result =
    await env.DB.prepare(
      `SELECT
         p.id,
         p.user_id,
         p.content,
         p.created_at,
         p.media_url,
         p.media_type,

         u.username,
         u.display_name,
         u.avatar_url,

         (
           SELECT COUNT(*)
           FROM likes l
           WHERE l.post_id = p.id
         ) AS likes_count,

         (
           SELECT COUNT(*)
           FROM comments c
           WHERE c.post_id = p.id
         ) AS comments_count,

         EXISTS(
           SELECT 1
           FROM likes l2
           WHERE l2.post_id = p.id
             AND l2.user_id = ?
         ) AS liked,

         EXISTS(
           SELECT 1
           FROM saved_posts sp
           WHERE sp.post_id =
             CAST(p.id AS TEXT)
             AND sp.user_id = ?
         ) AS saved

       FROM posts p

       JOIN users u
         ON u.id = p.user_id

       WHERE
         p.user_id = ?

         OR p.user_id IN (
           SELECT following_id
           FROM follows
           WHERE follower_id = ?
         )

       ORDER BY p.id DESC

       LIMIT 100`
    )
      .bind(
        userId,
        String(userId),
        userId,
        userId
      )
      .all();

  return json({
    posts:
      (result.results || [])
        .map(formatPost)
  });
}


// ============================================================
// CREATE POST
// ============================================================

async function createPost(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const content =
    body.content !== undefined
      ? String(body.content)
          .slice(0, 5000)
      : "";

  const mediaUrl =
    body.mediaUrl !== undefined
      ? String(body.mediaUrl)
          .slice(0, 2000)
      : String(
          body.media_url || ""
        ).slice(0, 2000);

  const mediaType =
    body.mediaType !== undefined
      ? String(body.mediaType)
          .slice(0, 100)
      : String(
          body.media_type || ""
        ).slice(0, 100);

  if (
    !content.trim() &&
    !mediaUrl
  ) {
    throw new HttpError(
      400,
      "Post cannot be empty"
    );
  }

  const result =
    await env.DB.prepare(
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
        Number(user.id),
        content,
        mediaUrl,
        mediaType
      )
      .run();

  const postId =
    Number(
      result.meta.last_row_id
    );

  const post =
    await getPostRow(
      postId,
      env
    );

  return json(
    {
      post:
        formatPost(post)
    },
    201
  );
}


// ============================================================
// GET SINGLE POST
// ============================================================

async function getPost(
  postId,
  user,
  env
) {
  if (
    !Number.isInteger(postId) ||
    postId <= 0
  ) {
    throw new HttpError(
      400,
      "Invalid post ID"
    );
  }

  const post =
    await env.DB.prepare(
      `SELECT
         p.id,
         p.user_id,
         p.content,
         p.created_at,
         p.media_url,
         p.media_type,

         u.username,
         u.display_name,
         u.avatar_url,

         (
           SELECT COUNT(*)
           FROM likes l
           WHERE l.post_id = p.id
         ) AS likes_count,

         (
           SELECT COUNT(*)
           FROM comments c
           WHERE c.post_id = p.id
         ) AS comments_count,

         EXISTS(
           SELECT 1
           FROM likes l2
           WHERE l2.post_id = p.id
             AND l2.user_id = ?
         ) AS liked,

         EXISTS(
           SELECT 1
           FROM saved_posts sp
           WHERE sp.post_id =
             CAST(p.id AS TEXT)
             AND sp.user_id = ?
         ) AS saved

       FROM posts p

       JOIN users u
         ON u.id = p.user_id

       WHERE p.id = ?

       LIMIT 1`
    )
      .bind(
        Number(user.id),
        String(user.id),
        postId
      )
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  return json({
    post:
      formatPost(post)
  });
}


// ============================================================
// DELETE POST
// ============================================================

async function deletePost(
  postId,
  user,
  env
) {
  const post =
    await env.DB.prepare(
      `SELECT
         id,
         user_id
       FROM posts
       WHERE id = ?
       LIMIT 1`
    )
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

  await env.DB.prepare(
    `DELETE FROM comments
     WHERE post_id = ?`
  )
    .bind(postId)
    .run();

  await env.DB.prepare(
    `DELETE FROM likes
     WHERE post_id = ?`
  )
    .bind(postId)
    .run();

  await env.DB.prepare(
    `DELETE FROM saved_posts
     WHERE post_id = ?`
  )
    .bind(String(postId))
    .run();

  await env.DB.prepare(
    `DELETE FROM notifications
     WHERE post_id = ?`
  )
    .bind(postId)
    .run();

  await env.DB.prepare(
    `DELETE FROM posts
     WHERE id = ?`
  )
    .bind(postId)
    .run();

  return json({
    ok: true
  });
}


// ============================================================
// LIKE
// ============================================================

async function toggleLike(
  postId,
  user,
  env
) {
  const post =
    await env.DB.prepare(
      `SELECT
         id,
         user_id
       FROM posts
       WHERE id = ?
       LIMIT 1`
    )
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  const userId =
    Number(user.id);

  const existing =
    await env.DB.prepare(
      `SELECT id
       FROM likes
       WHERE post_id = ?
         AND user_id = ?
       LIMIT 1`
    )
      .bind(
        postId,
        userId
      )
      .first();

  if (existing) {
    await env.DB.prepare(
      `DELETE FROM likes
       WHERE post_id = ?
         AND user_id = ?`
    )
      .bind(
        postId,
        userId
      )
      .run();

    return json({
      liked: false,

      likes_count:
        await getLikeCount(
          postId,
          env
        )
    });
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO likes
      (
        post_id,
        user_id
      )
     VALUES (?, ?)`
  )
    .bind(
      postId,
      userId
    )
    .run();

  if (
    Number(post.user_id) !==
    userId
  ) {
    await createNotification(
      env,
      Number(post.user_id),
      userId,
      "like",
      postId
    );
  }

  return json({
    liked: true,

    likes_count:
      await getLikeCount(
        postId,
        env
      )
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
    await env.DB.prepare(
      `SELECT id
       FROM posts
       WHERE id = ?
       LIMIT 1`
    )
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  const result =
    await env.DB.prepare(
      `SELECT
         c.id,
         c.post_id,
         c.user_id,
         c.content,
         c.created_at,

         u.username,
         u.display_name,
         u.avatar_url

       FROM comments c

       JOIN users u
         ON u.id = c.user_id

       WHERE c.post_id = ?

       ORDER BY c.id ASC

       LIMIT 200`
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
  postId,
  user,
  env
) {
  const body =
    await readJSON(request);

  const content =
    String(
      body.content || ""
    )
      .trim()
      .slice(0, 2000);

  if (!content) {
    throw new HttpError(
      400,
      "Comment cannot be empty"
    );
  }

  const post =
    await env.DB.prepare(
      `SELECT
         id,
         user_id
       FROM posts
       WHERE id = ?
       LIMIT 1`
    )
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  const result =
    await env.DB.prepare(
      `INSERT INTO comments
        (
          post_id,
          user_id,
          content
        )
       VALUES (?, ?, ?)`
    )
      .bind(
        postId,
        Number(user.id),
        content
      )
      .run();

  const commentId =
    Number(
      result.meta.last_row_id
    );

  if (
    Number(post.user_id) !==
    Number(user.id)
  ) {
    await createNotification(
      env,
      Number(post.user_id),
      Number(user.id),
      "comment",
      postId
    );
  }

  const comment =
    await env.DB.prepare(
      `SELECT
         c.id,
         c.post_id,
         c.user_id,
         c.content,
         c.created_at,

         u.username,
         u.display_name,
         u.avatar_url

       FROM comments c

       JOIN users u
         ON u.id = c.user_id

       WHERE c.id = ?

       LIMIT 1`
    )
      .bind(commentId)
      .first();

  return json(
    {
      comment
    },
    201
  );
}


// ============================================================
// SAVE
// ============================================================

async function toggleSave(
  postId,
  user,
  env
) {
  const post =
    await env.DB.prepare(
      `SELECT id
       FROM posts
       WHERE id = ?
       LIMIT 1`
    )
      .bind(postId)
      .first();

  if (!post) {
    throw new HttpError(
      404,
      "Post not found"
    );
  }

  const userId =
    String(user.id);

  const existing =
    await env.DB.prepare(
      `SELECT post_id
       FROM saved_posts
       WHERE post_id = ?
         AND user_id = ?
       LIMIT 1`
    )
      .bind(
        String(postId),
        userId
      )
      .first();

  if (existing) {
    await env.DB.prepare(
      `DELETE FROM saved_posts
       WHERE post_id = ?
         AND user_id = ?`
    )
      .bind(
        String(postId),
        userId
      )
      .run();

    return json({
      saved: false
    });
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO saved_posts
      (
        post_id,
        user_id,
        created_at
      )
     VALUES (?, ?, ?)`
  )
    .bind(
      String(postId),
      userId,
      new Date().toISOString()
    )
    .run();

  return json({
    saved: true
  });
}


// ============================================================
// MEDIA UPLOAD
// ============================================================

async function uploadMedia(
  request,
  user,
  env
) {
  if (!env.MEDIA) {
    throw new HttpError(
      503,
      "Media storage is not configured"
    );
  }

  const contentType =
    request.headers.get(
      "content-type"
    ) || "";

  if (
    !contentType
      .toLowerCase()
      .startsWith(
        "multipart/form-data"
      )
  ) {
    throw new HttpError(
      400,
      "Upload must use multipart/form-data"
    );
  }

  const form =
    await request.formData();

  const file =
    form.get("file") ||
    form.get("media");

  if (
    !file ||
    typeof file === "string" ||
    typeof file.arrayBuffer !==
      "function"
  ) {
    throw new HttpError(
      400,
      "No file provided"
    );
  }

  const maxBytes =
    25 * 1024 * 1024;

  if (
    Number(file.size || 0) >
    maxBytes
  ) {
    throw new HttpError(
      413,
      "File is too large"
    );
  }

  const type =
    String(file.type || "")
      .toLowerCase();

  const allowedPrefixes = [
    "image/",
    "video/",
    "audio/"
  ];

  if (
    type &&
    !allowedPrefixes.some(
      prefix =>
        type.startsWith(prefix)
    )
  ) {
    throw new HttpError(
      400,
      "Unsupported media type"
    );
  }

  const originalName =
    String(
      file.name || "upload"
    )
      .replace(
        /[^a-zA-Z0-9._-]/g,
        "_"
      )
      .slice(0, 100);

  const extension =
    getSafeExtension(
      originalName,
      type
    );

  const key =
    `users/${Number(user.id)}/` +
    `${Date.now()}-${randomId(12)}` +
    `${extension}`;

  await env.MEDIA.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType:
          type ||
          "application/octet-stream",

        contentDisposition:
          `inline; filename="${originalName}"`
      },

      customMetadata: {
        userId:
          String(user.id)
      }
    }
  );

  const mediaUrl =
    `${new URL(request.url).origin}` +
    `/media/${encodePath(key)}`;

  return json(
    {
      key,

      url:
        mediaUrl,

      media_url:
        mediaUrl,

      media_type:
        type ||
        "application/octet-stream"
    },
    201
  );
}


// ============================================================
// SERVE MEDIA
// ============================================================

async function serveMedia(
  path,
  env
) {
  if (!env.MEDIA) {
    return new Response(
      "Media storage unavailable",
      {
        status: 503
      }
    );
  }

  const key =
    decodeURIComponent(
      path.slice(
        "/media/".length
      )
    );

  if (!key) {
    return new Response(
      "Not found",
      {
        status: 404
      }
    );
  }

  const object =
    await env.MEDIA.get(key);

  if (!object) {
    return new Response(
      "Media not found",
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
    "etag",
    object.httpEtag
  );

  headers.set(
    "cache-control",
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


// ============================================================
// STORIES
// ============================================================

async function getStoryFeed(
  user,
  env
) {
  const userId =
    Number(user.id);

  const result =
    await env.DB.prepare(
      `SELECT
         s.id,
         s.user_id,
         s.content,
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
         datetime(s.created_at) >
           datetime(
             'now',
             '-24 hours'
           )

         AND (
           s.user_id = ?

           OR s.user_id IN (
             SELECT following_id
             FROM follows
             WHERE follower_id = ?
           )
         )

       ORDER BY s.id DESC`
    )
      .bind(
        userId,
        userId
      )
      .all();

  return json({
    stories:
      result.results || []
  });
}


async function createStory(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const content =
    body.content !== undefined
      ? String(body.content)
          .slice(0, 5000)
      : String(
          body.text || ""
        ).slice(0, 5000);

  const mediaUrl =
    body.mediaUrl !== undefined
      ? String(body.mediaUrl)
          .slice(0, 2000)
      : String(
          body.media_url || ""
        ).slice(0, 2000);

  const mediaType =
    body.mediaType !== undefined
      ? String(body.mediaType)
          .slice(0, 100)
      : String(
          body.media_type || ""
        ).slice(0, 100);

  if (
    !content.trim() &&
    !mediaUrl
  ) {
    throw new HttpError(
      400,
      "Story cannot be empty"
    );
  }

  const result =
    await env.DB.prepare(
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
        Number(user.id),
        content,
        mediaUrl,
        mediaType
      )
      .run();

  const storyId =
    Number(
      result.meta.last_row_id
    );

  const story =
    await env.DB.prepare(
      `SELECT
         s.id,
         s.user_id,
         s.content,
         s.media_url,
         s.media_type,
         s.created_at,

         u.username,
         u.display_name,
         u.avatar_url

       FROM stories s

       JOIN users u
         ON u.id = s.user_id

       WHERE s.id = ?

       LIMIT 1`
    )
      .bind(storyId)
      .first();

  return json(
    {
      story
    },
    201
  );
}


// ============================================================
// REELS
// ============================================================

async function getReels(
  env
) {
  const result =
    await env.DB.prepare(
      `SELECT
         r.id,
         r.user_id,
         r.caption,
         r.media_url,
         r.created_at,

         u.username,
         u.display_name,
         u.avatar_url

       FROM reels r

       JOIN users u
         ON u.id = r.user_id

       ORDER BY r.id DESC

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
  user,
  env
) {
  const body =
    await readJSON(request);

  const caption =
    String(
      body.caption || ""
    )
      .slice(0, 2000);

  const mediaUrl =
    body.mediaUrl !== undefined
      ? String(body.mediaUrl)
      : String(
          body.videoUrl ||
          body.media_url ||
          ""
        );

  if (!mediaUrl.trim()) {
    throw new HttpError(
      400,
      "Reel media URL is required"
    );
  }

  const result =
    await env.DB.prepare(
      `INSERT INTO reels
        (
          user_id,
          caption,
          media_url
        )
       VALUES (?, ?, ?)`
    )
      .bind(
        Number(user.id),
        caption,
        mediaUrl.slice(0, 2000)
      )
      .run();

  const reelId =
    Number(
      result.meta.last_row_id
    );

  const reel =
    await env.DB.prepare(
      `SELECT
         r.id,
         r.user_id,
         r.caption,
         r.media_url,
         r.created_at,

         u.username,
         u.display_name,
         u.avatar_url

       FROM reels r

       JOIN users u
         ON u.id = r.user_id

       WHERE r.id = ?

       LIMIT 1`
    )
      .bind(reelId)
      .first();

  return json(
    {
      reel
    },
    201
  );
}


// ============================================================
// POST HELPERS
// ============================================================

async function getPostRow(
  postId,
  env
) {
  return await env.DB.prepare(
    `SELECT
       p.id,
       p.user_id,
       p.content,
       p.created_at,
       p.media_url,
       p.media_type,

       u.username,
       u.display_name,
       u.avatar_url,

       (
         SELECT COUNT(*)
         FROM likes l
         WHERE l.post_id = p.id
       ) AS likes_count,

       (
         SELECT COUNT(*)
         FROM comments c
         WHERE c.post_id = p.id
       ) AS comments_count

     FROM posts p

     JOIN users u
       ON u.id = p.user_id

     WHERE p.id = ?

     LIMIT 1`
  )
    .bind(postId)
    .first();
}


function formatPost(post) {
  if (!post) {
    return null;
  }

  return {
    id:
      Number(post.id),

    user_id:
      Number(post.user_id),

    content:
      post.content || "",

    created_at:
      post.created_at || null,

    media_url:
      post.media_url || "",

    media_type:
      post.media_type || "",

    user: {
      id:
        Number(post.user_id),

      username:
        post.username || "",

      display_name:
        post.display_name || "",

      avatar_url:
        post.avatar_url || ""
    },

    likes_count:
      Number(
        post.likes_count || 0
      ),

    comments_count:
      Number(
        post.comments_count || 0
      ),

    liked:
      Boolean(
        Number(post.liked || 0)
      ),

    saved:
      Boolean(
        Number(post.saved || 0)
      )
  };
}


async function getLikeCount(
  postId,
  env
) {
  const row =
    await env.DB.prepare(
      `SELECT COUNT(*) AS count
       FROM likes
       WHERE post_id = ?`
    )
      .bind(postId)
      .first();

  return Number(
    row?.count || 0
  );
}


// ============================================================
// MEDIA HELPERS
// ============================================================

function getSafeExtension(
  filename,
  contentType
) {
  const match =
    filename.match(
      /\.([a-zA-Z0-9]{1,10})$/
    );

  if (match) {
    return "." +
      match[1].toLowerCase();
  }

  const map = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",

    "video/mp4": ".mp4",
    "video/webm": ".webm",

    "audio/mpeg": ".mp3",
    "audio/wav": ".wav",
    "audio/ogg": ".ogg"
  };

  return (
    map[contentType] ||
    ""
  );
}


function encodePath(value) {
  return value
    .split("/")
    .map(
      part =>
        encodeURIComponent(part)
    )
    .join("/");
}


// ============================================================
// CHATS
// ============================================================

async function getChats(
  user,
  env
) {
  const userId =
    Number(user.id);

  const result =
    await env.DB.prepare(
      `SELECT
         c.id,
         c.name,
         c.is_group,
         c.created_at,

         (
           SELECT m.content
           FROM messages m
           WHERE m.chat_id = c.id
           ORDER BY m.id DESC
           LIMIT 1
         ) AS last_message,

         (
           SELECT m.created_at
           FROM messages m
           WHERE m.chat_id = c.id
           ORDER BY m.id DESC
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
         ) DESC,

         c.id DESC`
    )
      .bind(userId)
      .all();

  const chats = [];

  for (
    const chat of
    result.results || []
  ) {
    const members =
      await env.DB.prepare(
        `SELECT
           u.id,
           u.username,
           u.display_name,
           u.avatar_url

         FROM chat_members cm

         JOIN users u
           ON u.id = cm.user_id

         WHERE cm.chat_id = ?

         ORDER BY cm.id ASC`
      )
        .bind(
          Number(chat.id)
        )
        .all();

    chats.push({
      id:
        Number(chat.id),

      name:
        chat.name || "",

      is_group:
        Number(chat.is_group || 0),

      type:
        Number(chat.is_group || 0) === 1
          ? "group"
          : "direct",

      created_at:
        chat.created_at,

      last_message:
        chat.last_message || "",

      last_message_at:
        chat.last_message_at || null,

      members:
        members.results || []
    });
  }

  return json({
    chats
  });
}


// ============================================================
// GET ONE CHAT
// ============================================================

async function getChat(
  chatId,
  user,
  env
) {
  await requireChatMember(
    chatId,
    Number(user.id),
    env
  );

  const chat =
    await env.DB.prepare(
      `SELECT
         id,
         name,
         is_group,
         created_at
       FROM chats
       WHERE id = ?
       LIMIT 1`
    )
      .bind(
        Number(chatId)
      )
      .first();

  if (!chat) {
    throw new HttpError(
      404,
      "Chat not found"
    );
  }

  const members =
    await env.DB.prepare(
      `SELECT
         u.id,
         u.username,
         u.display_name,
         u.avatar_url

       FROM chat_members cm

       JOIN users u
         ON u.id = cm.user_id

       WHERE cm.chat_id = ?

       ORDER BY cm.id ASC`
    )
      .bind(
        Number(chatId)
      )
      .all();

  return json({
    chat: {
      id:
        Number(chat.id),

      name:
        chat.name || "",

      is_group:
        Number(chat.is_group || 0),

      type:
        Number(chat.is_group || 0) === 1
          ? "group"
          : "direct",

      created_at:
        chat.created_at,

      members:
        members.results || []
    }
  });
}


// ============================================================
// CREATE DIRECT CHAT
// ============================================================

async function createChat(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const targetId =
    parsePositiveInt(
      body.userId ??
      body.user_id ??
      body.targetUserId ??
      body.target_user_id
    );

  if (!targetId) {
    throw new HttpError(
      400,
      "Valid user ID is required"
    );
  }

  if (
    targetId === Number(user.id)
  ) {
    throw new HttpError(
      400,
      "You cannot create a chat with yourself"
    );
  }

  const target =
    await getUserById(
      targetId,
      env
    );

  if (!target) {
    throw new HttpError(
      404,
      "User not found"
    );
  }

  // IMPORTANT:
  // The old worker had:
  // SELECT message_privacy
  //
  // That was wrong because message_privacy
  // belongs to user_settings.
  //
  // This version correctly uses s.message_privacy.

  const settings =
    await env.DB.prepare(
      `SELECT
         s.message_privacy
       FROM user_settings s
       WHERE s.user_id = ?
       LIMIT 1`
    )
      .bind(
        String(targetId)
      )
      .first();

  const privacy =
    settings?.message_privacy ||
    "everyone";

  if (
    privacy === "nobody"
  ) {
    throw new HttpError(
      403,
      "This user does not accept messages"
    );
  }

  if (
    privacy === "followers"
  ) {
    const follows =
      await env.DB.prepare(
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

    if (!follows) {
      throw new HttpError(
        403,
        "This user only accepts messages from followers"
      );
    }
  }

  const existing =
    await env.DB.prepare(
      `SELECT c.id
       FROM chats c

       JOIN chat_members cm1
         ON cm1.chat_id = c.id

       JOIN chat_members cm2
         ON cm2.chat_id = c.id

       WHERE c.is_group = 0

         AND cm1.user_id = ?

         AND cm2.user_id = ?

         AND (
           SELECT COUNT(*)
           FROM chat_members cm3
           WHERE cm3.chat_id = c.id
         ) = 2

       LIMIT 1`
    )
      .bind(
        Number(user.id),
        targetId
      )
      .first();

  if (existing) {
    return json({
      chat: {
        id:
          Number(existing.id),

        is_group: 0,

        type: "direct"
      },

      created: false
    });
  }

  const chatResult =
    await env.DB.prepare(
      `INSERT INTO chats
        (
          name,
          is_group
        )
       VALUES ('', 0)`
    )
      .run();

  const chatId =
    Number(
      chatResult.meta.last_row_id
    );

  if (!chatId) {
    throw new HttpError(
      500,
      "Could not create chat"
    );
  }

  await env.DB.prepare(
    `INSERT INTO chat_members
      (
        chat_id,
        user_id
      )
     VALUES (?, ?)`
  )
    .bind(
      chatId,
      Number(user.id)
    )
    .run();

  await env.DB.prepare(
    `INSERT INTO chat_members
      (
        chat_id,
        user_id
      )
     VALUES (?, ?)`
  )
    .bind(
      chatId,
      targetId
    )
    .run();

  return json(
    {
      chat: {
        id:
          chatId,

        name: "",

        is_group: 0,

        type: "direct"
      },

      created: true
    },
    201
  );
}


// ============================================================
// CHAT MEMBERSHIP
// ============================================================

async function requireChatMember(
  chatId,
  userId,
  env
) {
  const member =
    await env.DB.prepare(
      `SELECT
         cm.id,
         cm.chat_id,
         cm.user_id
       FROM chat_members cm
       WHERE cm.chat_id = ?
         AND cm.user_id = ?
       LIMIT 1`
    )
      .bind(
        Number(chatId),
        Number(userId)
      )
      .first();

  if (!member) {
    throw new HttpError(
      403,
      "You are not a member of this chat"
    );
  }

  return member;
}


// ============================================================
// MESSAGES
// ============================================================

async function getMessages(
  chatId,
  user,
  env
) {
  await requireChatMember(
    chatId,
    Number(user.id),
    env
  );

  const result =
    await env.DB.prepare(
      `SELECT
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

       ORDER BY m.id ASC

       LIMIT 500`
    )
      .bind(
        Number(chatId)
      )
      .all();

  return json({
    messages:
      result.results || []
  });
}


async function sendMessage(
  request,
  chatId,
  user,
  env
) {
  await requireChatMember(
    chatId,
    Number(user.id),
    env
  );

  const body =
    await readJSON(request);

  const content =
    String(
      body.content || ""
    )
      .trim()
      .slice(0, 5000);

  const mediaUrl =
    body.mediaUrl !== undefined
      ? String(body.mediaUrl)
          .slice(0, 2000)
      : String(
          body.media_url || ""
        ).slice(0, 2000);

  if (
    !content &&
    !mediaUrl
  ) {
    throw new HttpError(
      400,
      "Message cannot be empty"
    );
  }

  const result =
    await env.DB.prepare(
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
        Number(chatId),
        Number(user.id),
        content,
        mediaUrl
      )
      .run();

  const messageId =
    Number(
      result.meta.last_row_id
    );

  const message =
    await env.DB.prepare(
      `SELECT
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

       WHERE m.id = ?

       LIMIT 1`
    )
      .bind(messageId)
      .first();

  return json(
    {
      message
    },
    201
  );
}


// ============================================================
// GROUPS
// ============================================================

async function createGroup(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const name =
    String(
      body.name || ""
    )
      .trim()
      .slice(0, 100);

  if (!name) {
    throw new HttpError(
      400,
      "Group name is required"
    );
  }

  const inputMembers =
    body.userIds ??
    body.user_ids ??
    body.members ??
    [];

  if (
    !Array.isArray(inputMembers)
  ) {
    throw new HttpError(
      400,
      "Members must be an array"
    );
  }

  const memberIds = [
    Number(user.id),

    ...inputMembers
      .map(parsePositiveInt)
      .filter(Boolean)
  ];

  const uniqueIds = [
    ...new Set(memberIds)
  ];

  if (
    uniqueIds.length > 50
  ) {
    throw new HttpError(
      400,
      "A group can have at most 50 members"
    );
  }

  for (
    const memberId of uniqueIds
  ) {
    const member =
      await getUserById(
        memberId,
        env
      );

    if (!member) {
      throw new HttpError(
        400,
        `User ${memberId} does not exist`
      );
    }
  }

  const result =
    await env.DB.prepare(
      `INSERT INTO chats
        (
          name,
          is_group
        )
       VALUES (?, 1)`
    )
      .bind(name)
      .run();

  const chatId =
    Number(
      result.meta.last_row_id
    );

  if (!chatId) {
    throw new HttpError(
      500,
      "Could not create group"
    );
  }

  for (
    const memberId of uniqueIds
  ) {
    await env.DB.prepare(
      `INSERT INTO chat_members
        (
          chat_id,
          user_id
        )
       VALUES (?, ?)`
    )
      .bind(
        chatId,
        memberId
      )
      .run();
  }

  return json(
    {
      chat: {
        id:
          chatId,

        name,

        is_group: 1,

        type: "group",

        members:
          uniqueIds
      }
    },
    201
  );
}


// ============================================================
// NOTIFICATIONS
// ============================================================

async function createNotification(
  env,
  userId,
  actorId,
  type,
  postId
) {
  if (
    !userId ||
    !actorId ||
    Number(userId) ===
      Number(actorId)
  ) {
    return;
  }

  await env.DB.prepare(
    `INSERT INTO notifications
      (
        user_id,
        actor_id,
        type,
        post_id,
        is_read
      )
     VALUES (?, ?, ?, ?, 0)`
  )
    .bind(
      Number(userId),
      Number(actorId),
      String(type),

      postId === null
        ? null
        : Number(postId)
    )
    .run();
}


async function getNotifications(
  user,
  env
) {
  const result =
    await env.DB.prepare(
      `SELECT
         n.id,
         n.user_id,
         n.actor_id,
         n.type,
         n.post_id,
         n.created_at,
         n.is_read,

         u.username AS actor_username,
         u.display_name AS actor_display_name,
         u.avatar_url AS actor_avatar

       FROM notifications n

       LEFT JOIN users u
         ON u.id = n.actor_id

       WHERE n.user_id = ?

       ORDER BY n.id DESC

       LIMIT 100`
    )
      .bind(
        Number(user.id)
      )
      .all();

  return json({
    notifications:
      result.results || []
  });
}


async function markNotificationsRead(
  user,
  env
) {
  await env.DB.prepare(
    `UPDATE notifications
     SET is_read = 1
     WHERE user_id = ?
       AND is_read = 0`
  )
    .bind(
      Number(user.id)
    )
    .run();

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
  let settings =
    await env.DB.prepare(
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
      .bind(
        String(user.id)
      )
      .first();

  if (!settings) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO user_settings
        (
          user_id,
          theme,
          profile_visibility,
          message_privacy,
          notification_settings
        )
       VALUES (
         ?,
         'system',
         'public',
         'everyone',
         '{}'
       )`
    )
      .bind(
        String(user.id)
      )
      .run();

    settings =
      await env.DB.prepare(
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
        .bind(
          String(user.id)
        )
        .first();
  }

  return json({
    settings
  });
}


async function updateSettings(
  request,
  user,
  env
) {
  const body =
    await readJSON(request);

  const current =
    await env.DB.prepare(
      `SELECT
         theme,
         profile_visibility,
         message_privacy,
         notification_settings

       FROM user_settings

       WHERE user_id = ?

       LIMIT 1`
    )
      .bind(
        String(user.id)
      )
      .first();

  const theme =
    body.theme !== undefined
      ? normalizeTheme(
          body.theme
        )
      : (
          current?.theme ||
          "system"
        );

  const profileVisibility =
    body.profile_visibility !== undefined
      ? normalizeProfileVisibility(
          body.profile_visibility
        )
      : (
          current?.profile_visibility ||
          "public"
        );

  const messagePrivacy =
    body.message_privacy !== undefined
      ? normalizeMessagePrivacy(
          body.message_privacy
        )
      : (
          current?.message_privacy ||
          "everyone"
        );

  let notificationSettings =
    current?.notification_settings ||
    "{}";

  if (
    body.notification_settings !==
    undefined
  ) {
    if (
      typeof body.notification_settings ===
      "string"
    ) {
      try {
        JSON.parse(
          body.notification_settings
        );
      } catch {
        throw new HttpError(
          400,
          "Invalid notification settings JSON"
        );
      }

      notificationSettings =
        body.notification_settings;

    } else {
      try {
        notificationSettings =
          JSON.stringify(
            body.notification_settings
          );
      } catch {
        throw new HttpError(
          400,
          "Invalid notification settings"
        );
      }
    }
  }

  await env.DB.prepare(
    `INSERT INTO user_settings
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
       theme =
         excluded.theme,

       profile_visibility =
         excluded.profile_visibility,

       message_privacy =
         excluded.message_privacy,

       notification_settings =
         excluded.notification_settings`
  )
    .bind(
      String(user.id),
      theme,
      profileVisibility,
      messagePrivacy,
      notificationSettings
    )
    .run();

  // Keep users.is_private synchronized
  // with the profile visibility setting.

  await env.DB.prepare(
    `UPDATE users
     SET is_private = ?
     WHERE id = ?`
  )
    .bind(
      profileVisibility ===
        "private"
        ? 1
        : 0,

      Number(user.id)
    )
    .run();

  const settings =
    await env.DB.prepare(
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
      .bind(
        String(user.id)
      )
      .first();

  return json({
    settings
  });
}


// ============================================================
// SETTINGS VALIDATION
// ============================================================

function normalizeTheme(
  value
) {
  const theme =
    String(value || "")
      .trim()
      .toLowerCase();

  if (
    ![
      "system",
      "light",
      "dark"
    ].includes(theme)
  ) {
    throw new HttpError(
      400,
      "Invalid theme"
    );
  }

  return theme;
}


function normalizeProfileVisibility(
  value
) {
  const visibility =
    String(value || "")
      .trim()
      .toLowerCase();

  if (
    ![
      "public",
      "private"
    ].includes(visibility)
  ) {
    throw new HttpError(
      400,
      "Invalid profile visibility"
    );
  }

  return visibility;
}


function normalizeMessagePrivacy(
  value
) {
  const privacy =
    String(value || "")
      .trim()
      .toLowerCase();

  if (
    ![
      "everyone",
      "followers",
      "nobody"
    ].includes(privacy)
  ) {
    throw new HttpError(
      400,
      "Invalid message privacy"
    );
  }

  return privacy;
}


// ============================================================
// REQUEST / RESPONSE
// ============================================================

async function readJSON(
  request
) {
  try {
    const text =
      await request.text();

    if (!text.trim()) {
      return {};
    }

    return JSON.parse(text);

  } catch {
    throw new HttpError(
      400,
      "Invalid JSON body"
    );
  }
}


function json(
  data,
  status = 200,
  extraHeaders = {}
) {
  const headers =
    new Headers({
      "content-type":
        "application/json; charset=utf-8",

      ...corsHeaders(),

      ...extraHeaders
    });

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers
    }
  );
}


function corsHeaders() {
  return {
    "access-control-allow-origin":
      "*",

    "access-control-allow-methods":
      "GET,POST,PUT,PATCH,DELETE,OPTIONS",

    "access-control-allow-headers":
      "Content-Type, Authorization",

    "access-control-expose-headers":
      "Set-Cookie"
  };
}


function handleError(
  error
) {
  console.error(error);

  if (
    error instanceof HttpError
  ) {
    return json(
      {
        error:
          error.message
      },
      error.status
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


class HttpError extends Error {
  constructor(
    status,
    message
  ) {
    super(message);

    this.name =
      "HttpError";

    this.status =
      status;
  }
}


// ============================================================
// COOKIES
// ============================================================

function getSessionToken(
  request
) {
  const cookie =
    request.headers.get(
      "Cookie"
    ) || "";

  const match =
    cookie.match(
      /(?:^|;\s*)zilnet_session=([^;]+)/
    );

  if (match) {
    return decodeURIComponent(
      match[1]
    );
  }

  const authorization =
    request.headers.get(
      "Authorization"
    ) || "";

  if (
    authorization
      .toLowerCase()
      .startsWith("bearer ")
  ) {
    return authorization
      .slice(7)
      .trim();
  }

  return null;
}


function makeSessionCookie(
  token
) {
  return [
    `zilnet_session=${encodeURIComponent(token)}`,

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


// ============================================================
// CRYPTO
// ============================================================

function randomToken() {
  return randomId(48);
}


function randomId(
  length = 32
) {
  const bytes =
    crypto.getRandomValues(
      new Uint8Array(length)
    );

  return bytesToBase64Url(
    bytes
  );
}


function bytesToBase64Url(
  bytes
) {
  let binary = "";

  for (
    const byte of bytes
  ) {
    binary +=
      String.fromCharCode(
        byte
      );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


function bytesToBase64(
  bytes
) {
  let binary = "";

  for (
    const byte of bytes
  ) {
    binary +=
      String.fromCharCode(
        byte
      );
  }

  return btoa(binary);
}


function base64ToBytes(
  value
) {
  const binary =
    atob(value);

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


async function sha256(
  value
) {
  const data =
    new TextEncoder().encode(
      String(value)
    );

  const hash =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return bytesToBase64Url(
    new Uint8Array(hash)
  );
}


function timingSafeEqual(
  a,
  b
) {
  if (
    a.length !==
    b.length
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
// GENERAL HELPERS
// ============================================================

function parsePositiveInt(
  value
) {
  const number =
    Number(value);

  if (
    !Number.isInteger(number) ||
    number <= 0
  ) {
    return null;
  }

  return number;
}


async function countRows(
  env,
  sql,
  ...values
) {
  const row =
    await env.DB
      .prepare(sql)
      .bind(...values)
      .first();

  return Number(
    row?.count || 0
  );
}


function getOrigin(
  request
) {
  return new URL(
    request.url
  ).origin;
}


function escapeHtml(
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
