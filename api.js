export async function onRequestPost(context) {
  const { request, env, env: { DB } } = context;
  
  try {
    const { code } = await request.json();
    
    if (!code) {
      return new Response(JSON.stringify({ success: false, error: 'Code requis' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Récupérer l'utilisateur et son organisation
    const userQuery = await DB.prepare(`
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
        error: 'Code invalide' 
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Récupérer les projets de l'organisation
    const projectsQuery = await DB.prepare(`
      SELECT * FROM projects 
      WHERE organization_id = ?
      ORDER BY created_at DESC
    `).bind(userQuery.organization_id).all();
    
    // Compter les utilisateurs de l'organisation
    const usersCountQuery = await DB.prepare(`
      SELECT COUNT(*) as count FROM users 
      WHERE organization_id = ?
    `).bind(userQuery.organization_id).first();
    
    // Compter les projets de l'organisation
    const projectsCountQuery = await DB.prepare(`
      SELECT COUNT(*) as count FROM projects 
      WHERE organization_id = ?
    `).bind(userQuery.organization_id).first();
    
    const usersCount = usersCountQuery?.count || 0;
    const projectsCount = projectsCountQuery?.count || 0;
    
    return new Response(JSON.stringify({
      success: true,
      user: {
        id: userQuery.id,
        name: userQuery.name,
        email: userQuery.email,
        role: userQuery.role,
        department: userQuery.department
      },
      organization: {
        id: userQuery.organization_id,
        name: userQuery.organization_name,
        description: userQuery.organization_description,
        logo_url: userQuery.organization_logo
      },
      projects: projectsQuery.results || [],
      stats: {
        users: usersCount,
        projects: projectsCount,
        organizations: 1 // Pour cette démo
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    return new Response(JSON.stringify({ 
      success: false, 
      error: 'Erreur serveur' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
