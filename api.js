export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ✅ SERVIR LE SITE
    if (request.method === "GET" && url.pathname === "/") {
      return new Response(`<!DOCTYPE html>
<html>
<head>
  <title>Nexora</title>
</head>
<body>
  <h1>🚀 Nexora fonctionne!</h1>
  <p>Frontend connecté au backend</p>
</body>
</html>`, {
        headers: { "Content-Type": "text/html" }
      });
    }

    // ✅ LOGIN API
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const { code } = await request.json();

        const userQuery = await env.DB.prepare(`
          SELECT u.*, o.name as organization_name
          FROM users u
          JOIN organizations o ON u.organization_id = o.id
          WHERE u.code = ?
        `).bind(code).first();

        if (!userQuery) {
          return new Response(JSON.stringify({
            success: false,
            error: "Code invalide"
          }), { status: 401 });
        }

        return new Response(JSON.stringify({
          success: true,
          user: userQuery
        }), {
          headers: { "Content-Type": "application/json" }
        });

      } catch {
        return new Response("Erreur serveur", { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  }
};
