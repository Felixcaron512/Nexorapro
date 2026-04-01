import html from "./index.html";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ✅ Servir la page HTML
    if (request.method === "GET" && url.pathname === "/") {
      return new Response(html, {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    }

    // ✅ Petit test API
    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        success: true,
        message: "Nexora API OK"
      });
    }

    // ✅ Login
    if (request.method === "POST" && url.pathname === "/api/login") {
      try {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({
            success: false,
            error: "JSON invalide"
          }, 400);
        }

        const code = body?.code?.toString().trim();

        if (!code) {
          return json({
            success: false,
            error: "Code requis"
          }, 400);
        }

        // Récupérer utilisateur + organisation
        const userQuery = await env.DB.prepare(`
          SELECT 
            u.id,
            u.name,
            u.email,
            u.role,
            u.department,
            u.code,
            u.organization_id,
            o.name AS organization_name,
            o.description AS organization_description,
            o.logo_url AS organization_logo
          FROM users u
          JOIN organizations o ON u.organization_id = o.id
          WHERE u.code = ?
          LIMIT 1
        `).bind(code).first();

        if (!userQuery) {
          return json({
            success: false,
            error: "Code invalide"
          }, 401);
        }

        // Récupérer les projets
        const projectsQuery = await env.DB.prepare(`
          SELECT 
            id,
            name,
            description,
            status,
            created_at
          FROM projects
          WHERE organization_id = ?
          ORDER BY created_at DESC
        `).bind(userQuery.organization_id).all();

        // Compter les utilisateurs
        const usersCountQuery = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM users
          WHERE organization_id = ?
        `).bind(userQuery.organization_id).first();

        // Compter les projets
        const projectsCountQuery = await env.DB.prepare(`
          SELECT COUNT(*) AS count
          FROM projects
          WHERE organization_id = ?
        `).bind(userQuery.organization_id).first();

        return json({
          success: true,
          user: {
            id: userQuery.id,
            name: userQuery.name,
            email: userQuery.email,
            role: userQuery.role,
            department: userQuery.department,
            code: userQuery.code
          },
          organization: {
            id: userQuery.organization_id,
            name: userQuery.organization_name,
            description: userQuery.organization_description,
            logo_url: userQuery.organization_logo
          },
          projects: projectsQuery?.results || [],
          stats: {
            users: Number(usersCountQuery?.count || 0),
            projects: Number(projectsCountQuery?.count || 0),
            organizations: 1
          }
        });
      } catch (error) {
        return json({
          success: false,
          error: "Erreur serveur",
          details: error?.message || "Erreur inconnue"
        }, 500);
      }
    }

    // Méthode mauvaise sur route connue
    if (url.pathname === "/api/login") {
      return json({
        success: false,
        error: "Method Not Allowed"
      }, 405);
    }

    // Route inconnue
    return json({
      success: false,
      error: "Not Found"
    }, 404);
  }
};
