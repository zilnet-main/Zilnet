export default {
  async fetch(request, env) {
    const result = await env.DB
      .prepare("SELECT 1 AS connected")
      .first();

    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" }
    });
  }
};
