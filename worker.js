export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/test-db") {
      const result = await env.DB
        .prepare("SELECT 1 AS connected")
        .first();

      return Response.json(result);
    }

    if (url.pathname === "/api/comments" && request.method === "POST") {
      try {
        const data = await request.json();

        await env.DB
          .prepare(`
            INSERT INTO comments (post_id, user_id, content)
            VALUES (?, ?, ?)
          `)
          .bind(data.post_id, data.user_id, data.content)
          .run();

        return Response.json({ success: true });
      } catch (error) {
        return Response.json(
          { error: error.message },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
