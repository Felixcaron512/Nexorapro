export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ✅ TEST navigateur
    if (request.method === "GET" && url.pathname === "/") {
      return new Response("🚀 Nexora API OK", {
        headers: { "Content-Type": "text/plain" }
      });
    }

    // ✅ LOGIN
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const { code } = await request.json();

        if (!code) {
          return new Response(JSON.stringify({
            success: false,
            error: "Code requis"
          }), { status: 400 });
        }

        const userQuery = await env.DB.prepare(`
          SELECT 
            u.*, 
            o.name as organization_name,
            o.description as organization_description,
            o.logo_url as organization_logo
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

        const projectsQuery = await env.DB.prepare(`
          SELECT * FROM projects 
          WHERE organization_id = ?
        `).bind(userQuery.organization_id).all();

        const usersCount = await env.DB.prepare(`
          SELECT COUNT(*) as count FROM users WHERE organization_id = ?
        `).bind(userQuery.organization_id).first();

        const projectsCount = await env.DB.prepare(`
          SELECT COUNT(*) as count FROM projects WHERE organization_id = ?
        `).bind(userQuery.organization_id).first();

        return new Response(JSON.stringify({
          success: true,
          user: {
            id: userQuery.id,
            name: userQuery.name,
            email: userQuery.email,
            role: userQuery.role,
            department: userQuery.department,
            code: code // 🔥 IMPORTANT pour reload
          },
          organization: {
            id: userQuery.organization_id,
            name: userQuery.organization_name,
            description: userQuery.organization_description,
            logo_url: userQuery.organization_logo
          },
          projects: projectsQuery.results || [],
          stats: {
            users: usersCount?.count || 0,
            projects: projectsCount?.count || 0,
            organizations: 1
          }
        }), {
          headers: { "Content-Type": "application/json" }
        });

      } catch (err) {
        return new Response(JSON.stringify({
          success: false,
          error: "Erreur serveur"
        }), { status: 500 });
      }
    }

    // ❌ autre route
    return new Response("Not Found", { status: 404 });
  }
};
