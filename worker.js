export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // =========================
      // STATIC FILES
      // =========================
      if (!url.pathname.startsWith("/api/") &&
          !url.pathname.startsWith("/media/")) {
        return env.ASSETS.fetch(request);
      }

      // =========================
      // MEDIA
      // =========================
      if (url.pathname.startsWith("/media/")) {
        if (!env.MEDIA) {
          return new Response("Media storage is not configured", {
            status: 500
          });
        }

        const key = decodeURIComponent(
          url.pathname.replace("/media/", "")
        );

        const object = await env.MEDIA.get(key);

        if (!object) {
          return new Response("Not found", { status: 404 });
        }

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set("etag", object.httpEtag);
        headers.set("cache-control", "public, max-age=31536000");

        return new Response(object.body, { headers });
      }

      // =========================
      // TEST DB
      // =========================
      if (url.pathname === "/api/test-db") {
        const result = await env.DB
          .prepare("SELECT 1 AS connected")
          .first();

        return Response.json(result);
      }

      // =========================
      // SIGN UP
      // =========================
      if (url.pathname === "/api/signup" &&
          request.method === "POST") {

        const data = await request.json();

        const username = String(data.username || "")
          .trim()
          .toLowerCase();

        const email = String(data.email || "")
          .trim()
          .toLowerCase();

        const password = String(data.password || "");
        const displayName =
          String(data.display_name || username).trim();

        if (!username || !password) {
          return Response.json(
            { error: "Username and password are required" },
            { status: 400 }
          );
        }

        if (username.length < 3) {
          return Response.json(
            { error: "Username must be at least 3 characters" },
            { status: 400 }
          );
        }

        if (password.length < 6) {
          return Response.json(
            { error: "Password must be at least 6 characters" },
            { status: 400 }
          );
        }

        const existing = await env.DB
          .prepare(`
            SELECT id
            FROM users
            WHERE username = ?
               OR (? != '' AND email = ?)
          `)
          .bind(username, email, email)
          .first();

        if (existing) {
          return Response.json(
            { error: "Username or email already exists" },
            { status: 409 }
          );
        }

        const passwordData =
          await hashPassword(password);

        const result = await env.DB
          .prepare(`
            INSERT INTO users
            (
              username,
              email,
              display_name,
              password_hash,
              password_salt
            )
            VALUES (?, ?, ?, ?, ?)
          `)
          .bind(
            username,
            email || null,
            displayName,
            passwordData.hash,
            passwordData.salt
          )
          .run();

        const userId = result.meta.last_row_id;

        const sessionToken =
          crypto.randomUUID() +
          "-" +
          crypto.randomUUID();

        await env.DB
          .prepare(`
            INSERT INTO sessions
            (
              token,
              user_id,
              expires_at
            )
            VALUES (?, ?, datetime('now', '+30 days'))
          `)
          .bind(sessionToken, userId)
          .run();

        return withCookie(
          Response.json({
            success: true,
            user: {
              id: userId,
              username,
              email,
              display_name: displayName
            }
          }),
          sessionToken
        );
      }

      // =========================
      // LOGIN
      // =========================
      if (url.pathname === "/api/login" &&
          request.method === "POST") {

        const data = await request.json();

        const identifier = String(
          data.username ||
          data.email ||
          data.identifier ||
          ""
        ).trim().toLowerCase();

        const password = String(data.password || "");

        if (!identifier || !password) {
          return Response.json(
            { error: "Username and password are required" },
            { status: 400 }
          );
        }

        const user = await env.DB
          .prepare(`
            SELECT
              id,
              username,
              email,
              display_name,
              bio,
              avatar_url,
              skills,
              password_hash,
              password_salt,
              is_private
            FROM users
            WHERE username = ?
               OR email = ?
            LIMIT 1
          `)
          .bind(identifier, identifier)
          .first();

        if (!user) {
          return Response.json(
            { error: "Invalid username or password" },
            { status: 401 }
          );
        }

        if (!user.password_hash || !user.password_salt) {
          return Response.json(
            { error: "This account needs to be recreated" },
            { status: 401 }
          );
        }

        const valid =
          await verifyPassword(
            password,
            user.password_hash,
            user.password_salt
          );

        if (!valid) {
          return Response.json(
            { error: "Invalid username or password" },
            { status: 401 }
          );
        }

        const sessionToken =
          crypto.randomUUID() +
          "-" +
          crypto.randomUUID();

        await env.DB
          .prepare(`
            INSERT INTO sessions
            (
              token,
              user_id,
              expires_at
            )
            VALUES (?, ?, datetime('now', '+30 days'))
          `)
          .bind(sessionToken, user.id)
          .run();

        delete user.password_hash;
        delete user.password_salt;

        return withCookie(
          Response.json({
            success: true,
            user
          }),
          sessionToken
        );
      }

      // =========================
      // LOGOUT
      // =========================
      if (url.pathname === "/api/logout" &&
          request.method === "POST") {

        const token = getCookie(request, "zilnet_session");

        if (token) {
          await env.DB
            .prepare(`
              DELETE FROM sessions
              WHERE token = ?
            `)
            .bind(token)
            .run();
        }

        return new Response(
          JSON.stringify({ success: true }),
          {
            headers: {
              "content-type": "application/json",
              "set-cookie":
                "zilnet_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
            }
          }
        );
      }

      // =========================
      // CURRENT USER
      // =========================
      if (url.pathname === "/api/me" &&
          request.method === "GET") {

        const user = await getCurrentUser(request, env);

        if (!user) {
          return Response.json(
            { user: null },
            { status: 401 }
          );
        }

        return Response.json({ user });
      }

      // =========================
      // PROFILE UPDATE
      // =========================
      if (url.pathname === "/api/profile" &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const data = await request.json();

        const displayName =
          String(data.display_name ?? user.display_name ?? "")
            .trim();

        const bio =
          String(data.bio ?? user.bio ?? "")
            .trim();

        const skills =
          String(data.skills ?? user.skills ?? "")
            .trim();

        const avatarUrl =
          String(data.avatar_url ?? user.avatar_url ?? "")
            .trim();

        await env.DB
          .prepare(`
            UPDATE users
            SET
              display_name = ?,
              bio = ?,
              skills = ?,
              avatar_url = ?
            WHERE id = ?
          `)
          .bind(
            displayName,
            bio,
            skills,
            avatarUrl,
            user.id
          )
          .run();

        return Response.json({
          success: true
        });
      }

      // =========================
      // FEED
      // =========================
      if (url.pathname === "/api/feed" &&
          request.method === "GET") {

        const user = await getCurrentUser(request, env);

        if (!user) {
          return Response.json(
            { posts: [] }
          );
        }

        const posts = await env.DB
          .prepare(`
            SELECT
              p.id,
              p.user_id,
              p.content,
              p.created_at,
              u.username,
              u.display_name,
              u.avatar_url,
              (
                SELECT COUNT(*)
                FROM likes l
                WHERE l.post_id = p.id
              ) AS like_count,
              EXISTS(
                SELECT 1
                FROM likes l2
                WHERE l2.post_id = p.id
                  AND l2.user_id = ?
              ) AS liked
            FROM posts p
            JOIN users u
              ON u.id = p.user_id
            ORDER BY p.created_at DESC
            LIMIT 100
          `)
          .bind(user.id)
          .all();

        return Response.json({
          posts: posts.results || []
        });
      }

      // =========================
      // CREATE POST
      // =========================
      if (url.pathname === "/api/posts" &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const data = await request.json();

        const content =
          String(data.content || "").trim();

        const mediaUrl =
          String(data.media_url || "").trim();

        if (!content && !mediaUrl) {
          return Response.json(
            { error: "Post cannot be empty" },
            { status: 400 }
          );
        }

        const result = await env.DB
          .prepare(`
            INSERT INTO posts
            (
              user_id,
              content,
              media_url
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            user.id,
            content,
            mediaUrl || null
          )
          .run();

        return Response.json({
          success: true,
          post_id: result.meta.last_row_id
        });
      }

      // =========================
      // DELETE POST
      // =========================
      const deleteMatch =
        url.pathname.match(/^\/api\/posts\/(\d+)$/);

      if (deleteMatch &&
          request.method === "DELETE") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const postId =
          Number(deleteMatch[1]);

        await env.DB
          .prepare(`
            DELETE FROM comments
            WHERE post_id = ?
          `)
          .bind(postId)
          .run();

        await env.DB
          .prepare(`
            DELETE FROM likes
            WHERE post_id = ?
          `)
          .bind(postId)
          .run();

        const result = await env.DB
          .prepare(`
            DELETE FROM posts
            WHERE id = ?
              AND user_id = ?
          `)
          .bind(postId, user.id)
          .run();

        return Response.json({
          success: result.meta.changes > 0
        });
      }

      // =========================
      // LIKE
      // =========================
      const likeMatch =
        url.pathname.match(/^\/api\/posts\/(\d+)\/like$/);

      if (likeMatch &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const postId =
          Number(likeMatch[1]);

        const existing = await env.DB
          .prepare(`
            SELECT id
            FROM likes
            WHERE post_id = ?
              AND user_id = ?
          `)
          .bind(postId, user.id)
          .first();

        if (existing) {

          await env.DB
            .prepare(`
              DELETE FROM likes
              WHERE post_id = ?
                AND user_id = ?
            `)
            .bind(postId, user.id)
            .run();

          return Response.json({
            liked: false
          });

        } else {

          await env.DB
            .prepare(`
              INSERT INTO likes
              (
                post_id,
                user_id
              )
              VALUES (?, ?)
            `)
            .bind(postId, user.id)
            .run();

          return Response.json({
            liked: true
          });
        }
      }

      // =========================
      // COMMENTS
      // =========================
      if (url.pathname === "/api/comments" &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const data = await request.json();

        const postId = Number(data.post_id);
        const content =
          String(data.content || "").trim();

        if (!postId || !content) {
          return Response.json(
            { error: "Invalid comment" },
            { status: 400 }
          );
        }

        await env.DB
          .prepare(`
            INSERT INTO comments
            (
              post_id,
              user_id,
              content
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            postId,
            user.id,
            content
          )
          .run();

        return Response.json({
          success: true
        });
      }

      const commentsMatch =
        url.pathname.match(
          /^\/api\/posts\/(\d+)\/comments$/
        );

      if (commentsMatch &&
          request.method === "GET") {

        const postId =
          Number(commentsMatch[1]);

        const comments = await env.DB
          .prepare(`
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
          `)
          .bind(postId)
          .all();

        return Response.json({
          comments: comments.results || []
        });
      }

      // =========================
      // FOLLOW / UNFOLLOW
      // =========================
      const followMatch =
        url.pathname.match(
          /^\/api\/users\/(\d+)\/follow$/
        );

      if (followMatch &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const targetId =
          Number(followMatch[1]);

        if (targetId === user.id) {
          return Response.json(
            { error: "You cannot follow yourself" },
            { status: 400 }
          );
        }

        const existing = await env.DB
          .prepare(`
            SELECT id
            FROM follows
            WHERE follower_id = ?
              AND following_id = ?
          `)
          .bind(user.id, targetId)
          .first();

        if (existing) {

          await env.DB
            .prepare(`
              DELETE FROM follows
              WHERE follower_id = ?
                AND following_id = ?
            `)
            .bind(user.id, targetId)
            .run();

          return Response.json({
            following: false
          });

        } else {

          await env.DB
            .prepare(`
              INSERT INTO follows
              (
                follower_id,
                following_id
              )
              VALUES (?, ?)
            `)
            .bind(user.id, targetId)
            .run();

          return Response.json({
            following: true
          });
        }
      }

      // =========================
      // SEARCH
      // =========================
      if (url.pathname === "/api/search" &&
          request.method === "GET") {

        const q =
          String(url.searchParams.get("q") || "")
            .trim()
            .toLowerCase();

        if (!q) {
          return Response.json({
            users: []
          });
        }

        const results = await env.DB
          .prepare(`
            SELECT
              id,
              username,
              display_name,
              avatar_url,
              bio,
              skills
            FROM users
            WHERE username LIKE ?
               OR display_name LIKE ?
               OR skills LIKE ?
            ORDER BY username
            LIMIT 50
          `)
          .bind(
            `%${q}%`,
            `%${q}%`,
            `%${q}%`
          )
          .all();

        return Response.json({
          users: results.results || []
        });
      }

      // =========================
      // USER PROFILE
      // =========================
      const profileMatch =
        url.pathname.match(
          /^\/api\/users\/(\d+)$/
        );

      if (profileMatch &&
          request.method === "GET") {

        const userId =
          Number(profileMatch[1]);

        const profile = await env.DB
          .prepare(`
            SELECT
              id,
              username,
              email,
              display_name,
              bio,
              avatar_url,
              skills,
              is_private,
              created_at
            FROM users
            WHERE id = ?
          `)
          .bind(userId)
          .first();

        if (!profile) {
          return Response.json(
            { error: "User not found" },
            { status: 404 }
          );
        }

        const followers = await env.DB
          .prepare(`
            SELECT COUNT(*) AS count
            FROM follows
            WHERE following_id = ?
          `)
          .bind(userId)
          .first();

        const following = await env.DB
          .prepare(`
            SELECT COUNT(*) AS count
            FROM follows
            WHERE follower_id = ?
          `)
          .bind(userId)
          .first();

        const posts = await env.DB
          .prepare(`
            SELECT
              id,
              content,
              media_url,
              created_at
            FROM posts
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
          `)
          .bind(userId)
          .all();

        return Response.json({
          user: profile,
          followers: Number(followers?.count || 0),
          following: Number(following?.count || 0),
          posts: posts.results || []
        });
      }

      // =========================
      // SUGGESTIONS
      // =========================
      if (url.pathname === "/api/suggestions" &&
          request.method === "GET") {

        const user = await getCurrentUser(request, env);

        if (!user) {
          return Response.json({
            users: []
          });
        }

        const suggestions = await env.DB
          .prepare(`
            SELECT
              id,
              username,
              display_name,
              avatar_url,
              bio,
              skills
            FROM users
            WHERE id != ?
              AND id NOT IN (
                SELECT following_id
                FROM follows
                WHERE follower_id = ?
              )
            ORDER BY RANDOM()
            LIMIT 10
          `)
          .bind(user.id, user.id)
          .all();

        return Response.json({
          users: suggestions.results || []
        });
      }

      // =========================
      // STORIES
      // =========================
      if (url.pathname === "/api/stories" &&
          request.method === "GET") {

        const user = await getCurrentUser(request, env);

        if (!user) {
          return Response.json({
            stories: []
          });
        }

        const stories = await env.DB
          .prepare(`
            SELECT
              s.id,
              s.user_id,
              s.content,
              s.media_url,
              s.visibility,
              s.created_at,
              u.username,
              u.display_name,
              u.avatar_url
            FROM stories s
            JOIN users u
              ON u.id = s.user_id
            WHERE datetime(
                    s.created_at,
                    '+24 hours'
                  ) > datetime('now')
              AND (
                s.user_id = ?
                OR s.visibility = 'public'
                OR (
                  s.visibility = 'followers'
                  AND EXISTS (
                    SELECT 1
                    FROM follows f
                    WHERE f.follower_id = ?
                      AND f.following_id = s.user_id
                  )
                )
              )
            ORDER BY s.created_at DESC
          `)
          .bind(user.id, user.id)
          .all();

        return Response.json({
          stories: stories.results || []
        });
      }

      // CREATE STORY
      if (url.pathname === "/api/stories" &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const data = await request.json();

        const content =
          String(data.content || "").trim();

        const mediaUrl =
          String(data.media_url || "").trim();

        const visibility =
          data.visibility === "followers"
            ? "followers"
            : "public";

        if (!content && !mediaUrl) {
          return Response.json(
            { error: "Story cannot be empty" },
            { status: 400 }
          );
        }

        await env.DB
          .prepare(`
            INSERT INTO stories
            (
              user_id,
              content,
              media_url,
              visibility
            )
            VALUES (?, ?, ?, ?)
          `)
          .bind(
            user.id,
            content,
            mediaUrl || null,
            visibility
          )
          .run();

        return Response.json({
          success: true
        });
      }

      // =========================
      // REELS
      // =========================
      if (url.pathname === "/api/reels" &&
          request.method === "GET") {

        const reels = await env.DB
          .prepare(`
            SELECT
              r.id,
              r.user_id,
              r.media_url,
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
          `)
          .all();

        return Response.json({
          reels: reels.results || []
        });
      }

      if (url.pathname === "/api/reels" &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const data = await request.json();

        const mediaUrl =
          String(data.media_url || "").trim();

        const caption =
          String(data.caption || "").trim();

        if (!mediaUrl) {
          return Response.json(
            { error: "Reel video is required" },
            { status: 400 }
          );
        }

        await env.DB
          .prepare(`
            INSERT INTO reels
            (
              user_id,
              media_url,
              caption
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            user.id,
            mediaUrl,
            caption
          )
          .run();

        return Response.json({
          success: true
        });
      }

      // =========================
      // CHATS
      // =========================
      if (url.pathname === "/api/chats" &&
          request.method === "GET") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const chats = await env.DB
          .prepare(`
            SELECT
              c.id,
              c.name,
              c.is_group,
              c.created_at
            FROM chats c
            JOIN chat_members cm
              ON cm.chat_id = c.id
            WHERE cm.user_id = ?
            ORDER BY c.created_at DESC
          `)
          .bind(user.id)
          .all();

        return Response.json({
          chats: chats.results || []
        });
      }

      // =========================
      // CHAT MESSAGES
      // =========================
      const messagesMatch =
        url.pathname.match(
          /^\/api\/chats\/(\d+)\/messages$/
        );

      if (messagesMatch &&
          request.method === "GET") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const chatId =
          Number(messagesMatch[1]);

        const member = await env.DB
          .prepare(`
            SELECT id
            FROM chat_members
            WHERE chat_id = ?
              AND user_id = ?
          `)
          .bind(chatId, user.id)
          .first();

        if (!member) {
          return Response.json(
            { error: "Not a member of this chat" },
            { status: 403 }
          );
        }

        const messages = await env.DB
          .prepare(`
            SELECT
              m.id,
              m.chat_id,
              m.user_id,
              m.content,
              m.created_at,
              u.username,
              u.display_name,
              u.avatar_url
            FROM messages m
            JOIN users u
              ON u.id = m.user_id
            WHERE m.chat_id = ?
            ORDER BY m.created_at ASC
            LIMIT 200
          `)
          .bind(chatId)
          .all();

        return Response.json({
          messages: messages.results || []
        });
      }

      if (messagesMatch &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const chatId =
          Number(messagesMatch[1]);

        const member = await env.DB
          .prepare(`
            SELECT id
            FROM chat_members
            WHERE chat_id = ?
              AND user_id = ?
          `)
          .bind(chatId, user.id)
          .first();

        if (!member) {
          return Response.json(
            { error: "Not a member of this chat" },
            { status: 403 }
          );
        }

        const data = await request.json();

        const content =
          String(data.content || "").trim();

        if (!content) {
          return Response.json(
            { error: "Message cannot be empty" },
            { status: 400 }
          );
        }

        const result = await env.DB
          .prepare(`
            INSERT INTO messages
            (
              chat_id,
              user_id,
              content
            )
            VALUES (?, ?, ?)
          `)
          .bind(
            chatId,
            user.id,
            content
          )
          .run();

        return Response.json({
          success: true,
          message_id: result.meta.last_row_id
        });
      }

      // =========================
      // NOTIFICATIONS
      // =========================
      if (url.pathname === "/api/notifications" &&
          request.method === "GET") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { notifications: [] }
          );
        }

        const notifications = await env.DB
          .prepare(`
            SELECT
              n.id,
              n.message,
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
          `)
          .bind(user.id)
          .all();

        return Response.json({
          notifications:
            notifications.results || []
        });
      }

      // =========================
      // PRIVACY SETTINGS
      // =========================
      if (url.pathname === "/api/settings/privacy" &&
          request.method === "GET") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const settings = await env.DB
          .prepare(`
            SELECT is_private
            FROM users
            WHERE id = ?
          `)
          .bind(user.id)
          .first();

        return Response.json({
          settings: settings || {
            is_private: 0
          }
        });
      }

      if (url.pathname === "/api/settings/privacy" &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        const data = await request.json();

        const isPrivate =
          data.is_private ? 1 : 0;

        await env.DB
          .prepare(`
            UPDATE users
            SET is_private = ?
            WHERE id = ?
          `)
          .bind(isPrivate, user.id)
          .run();

        return Response.json({
          success: true
        });
      }

      // =========================
      // UPLOAD TO R2
      // =========================
      if (url.pathname === "/api/upload" &&
          request.method === "POST") {

        const user = await requireUser(request, env);

        if (!user) {
          return Response.json(
            { error: "Not logged in" },
            { status: 401 }
          );
        }

        if (!env.MEDIA) {
          return Response.json(
            { error: "Media storage is not configured" },
            { status: 500 }
          );
        }

        const form = await request.formData();

        const file = form.get("file");
        const type =
          String(form.get("type") || "media");

        if (!(file instanceof File)) {
          return Response.json(
            { error: "No file uploaded" },
            { status: 400 }
          );
        }

        if (file.size > 50 * 1024 * 1024) {
          return Response.json(
            { error: "File is too large" },
            { status: 413 }
          );
        }

        const extension =
          getExtension(file.name, file.type);

        const key =
          `${type}/${user.id}/${Date.now()}-${crypto.randomUUID()}${extension}`;

        await env.MEDIA.put(
          key,
          file.stream(),
          {
            httpMetadata: {
              contentType:
                file.type || "application/octet-stream"
            }
          }
        );

        return Response.json({
          success: true,
          key,
          url: `/media/${encodeURIComponent(key)}`
        });
      }

      return Response.json(
        { error: "API endpoint not found" },
        { status: 404 }
      );

    } catch (error) {

      console.error(error);

      return Response.json(
        {
          error:
            error?.message ||
            "Internal server error"
        },
        { status: 500 }
      );
    }
  }
};


// ======================================
// PASSWORD FUNCTIONS
// ======================================

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
      "PBKDF2",
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
    salt,
    hash: bytesToBase64(
      new Uint8Array(bits)
    )
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
      "PBKDF2",
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

  const hash =
    bytesToBase64(
      new Uint8Array(bits)
    );

  return hash === storedHash;
}


// ======================================
// AUTH HELPERS
// ======================================

async function getCurrentUser(request, env) {

  const token =
    getCookie(request, "zilnet_session");

  if (!token) return null;

  const result = await env.DB
    .prepare(`
      SELECT
        u.id,
        u.username,
        u.email,
        u.display_name,
        u.bio,
        u.avatar_url,
        u.skills,
        u.is_private,
        u.created_at
      FROM sessions s
      JOIN users u
        ON u.id = s.user_id
      WHERE s.token = ?
        AND datetime(s.expires_at) > datetime('now')
      LIMIT 1
    `)
    .bind(token)
    .first();

  return result || null;
}


async function requireUser(request, env) {
  return await getCurrentUser(request, env);
}


// ======================================
// COOKIE HELPERS
// ======================================

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


function withCookie(response, token) {

  const headers =
    new Headers(response.headers);

  headers.append(
    "Set-Cookie",
    `zilnet_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
  );

  return new Response(
    response.body,
    {
      status: response.status,
      statusText: response.statusText,
      headers
    }
  );
}


// ======================================
// BASE64 HELPERS
// ======================================

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
    new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}


// ======================================
// FILE EXTENSION
// ======================================

function getExtension(name, mime) {

  const known = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/quicktime": ".mov"
  };

  if (known[mime]) {
    return known[mime];
  }

  const match =
    String(name || "")
      .match(/\.[a-zA-Z0-9]+$/);

  return match ? match[0] : "";
}
