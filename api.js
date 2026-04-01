import html from "./index.html";

const SESSION_COOKIE = "nexora_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 jours

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function htmlResponse(content, status = 200) {
  return new Response(content, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function normalizeRole(role) {
  const allowed = ["user", "manager", "admin", "superadmin"];
  return allowed.includes(role) ? role : "user";
}

function canManageUsers(role) {
  return ["admin", "superadmin"].includes(role);
}

function canManageProjects(role) {
  return ["manager", "admin", "superadmin"].includes(role);
}

function isSuperAdmin(role) {
  return role === "superadmin";
}

function parseCookies(request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = {};
  for (const part of cookieHeader.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (!key) continue;
    cookies[key] = decodeURIComponent(rest.join("="));
  }
  return cookies;
}

function makeSetCookie(name, value, maxAgeSeconds, options = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`
  ];

  if (options.secure !== false) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure`;
}

function toBase64Url(inputBytes) {
  let binary = "";
  const bytes = inputBytes instanceof Uint8Array ? inputBytes : new Uint8Array(inputBytes);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function hmacSign(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );

  return toBase64Url(new Uint8Array(signature));
}

async function createSessionToken(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);

  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + SESSION_TTL_SECONDS
  };

  const encodedHeader = toBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const encodedPayload = toBase64Url(new TextEncoder().encode(JSON.stringify(fullPayload)));
  const unsigned = `${encodedHeader}.${encodedPayload}`;
  const signature = await hmacSign(unsigned, secret);

  return `${unsigned}.${signature}`;
}

async function verifySessionToken(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, signature] = parts;
    const unsigned = `${encodedHeader}.${encodedPayload}`;
    const expectedSignature = await hmacSign(unsigned, secret);

    if (expectedSignature !== signature) return null;

    const payloadJson = new TextDecoder().decode(fromBase64Url(encodedPayload));
    const payload = JSON.parse(payloadJson);

    if (!payload.exp || Math.floor(Date.now() / 1000) > payload.exp) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

async function derivePasswordHash(password, saltBase64 = null) {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const salt = saltBase64 ? fromBase64Url(saltBase64) : crypto.getRandomValues(new Uint8Array(16));
  const iterations = 120000;

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations
    },
    passwordKey,
    256
  );

  const hashBase64 = toBase64Url(new Uint8Array(bits));
  const saltEncoded = toBase64Url(salt);

  return {
    full: `pbkdf2$${iterations}$${saltEncoded}$${hashBase64}`,
    iterations,
    salt: saltEncoded,
    hash: hashBase64
  };
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

    const [, iterationsStr, salt, expectedHash] = parts;
    const iterations = Number(iterationsStr);

    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: fromBase64Url(salt),
        iterations
      },
      passwordKey,
      256
    );

    const actualHash = toBase64Url(new Uint8Array(bits));
    return actualHash === expectedHash;
  } catch {
    return false;
  }
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function getAuthUser(request, env) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;

  const secret = env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET manquant");

  const payload = await verifySessionToken(token, secret);
  if (!payload?.userId) return null;

  const user = await env.DB.prepare(`
    SELECT
      u.id,
      u.organization_id,
      u.name,
      u.email,
      u.role,
      u.department,
      u.is_active,
      o.name AS organization_name,
      o.slug AS organization_slug,
      o.description AS organization_description,
      o.logo_url AS organization_logo
    FROM users u
    JOIN organizations o ON o.id = u.organization_id
    WHERE u.id = ?
    LIMIT 1
  `).bind(payload.userId).first();

  if (!user || Number(user.is_active) !== 1) return null;
  return user;
}

async function requireAuth(request, env) {
  const user = await getAuthUser(request, env);
  if (!user) {
    return {
      error: json({ success: false, error: "Non authentifié" }, 401)
    };
  }
  return { user };
}

async function ensureSchema(env) {
  const statements = [
    `
    CREATE TABLE IF NOT EXISTS organizations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      description TEXT DEFAULT '',
      logo_url TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      department TEXT DEFAULT '',
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (organization_id, email),
      FOREIGN KEY (organization_id) REFERENCES organizations(id)
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      status TEXT NOT NULL DEFAULT 'active',
      owner_user_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (organization_id) REFERENCES organizations(id),
      FOREIGN KEY (owner_user_id) REFERENCES users(id)
    )
    `,
    `
    CREATE TABLE IF NOT EXISTS activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER,
      user_id INTEGER,
      action TEXT NOT NULL,
      details TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    `
  ];

  for (const sql of statements) {
    await env.DB.prepare(sql).run();
  }
}

async function logActivity(env, organizationId, userId, action, details = "") {
  try {
    await env.DB.prepare(`
      INSERT INTO activity_logs (organization_id, user_id, action, details)
      VALUES (?, ?, ?, ?)
    `).bind(organizationId || null, userId || null, action, details).run();
  } catch {
    // ignore logging errors
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    await ensureSchema(env);

    if (!env.JWT_SECRET) {
      return json({
        success: false,
        error: "Configure un secret avec: npx wrangler secret put JWT_SECRET"
      }, 500);
    }

    // Frontend
    if (request.method === "GET" && url.pathname === "/") {
      return htmlResponse(html);
    }

    // Health
    if (request.method === "GET" && url.pathname === "/api/health") {
      return json({ success: true, message: "Nexora API OK" });
    }

    // Bootstrap status
    if (request.method === "GET" && url.pathname === "/api/bootstrap/status") {
      const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM users`).first();
      return json({
        success: true,
        initialized: Number(countRow?.count || 0) > 0
      });
    }

    // Bootstrap initial
    if (request.method === "POST" && url.pathname === "/api/bootstrap") {
      const countRow = await env.DB.prepare(`SELECT COUNT(*) AS count FROM users`).first();
      if (Number(countRow?.count || 0) > 0) {
        return json({
          success: false,
          error: "Le système est déjà initialisé"
        }, 400);
      }

      const body = await readJson(request);
      if (!body) {
        return json({ success: false, error: "JSON invalide" }, 400);
      }

      const orgName = (body.organization_name || "").trim();
      const orgSlug = (body.organization_slug || "").trim().toLowerCase();
      const adminName = (body.name || "").trim();
      const adminEmail = (body.email || "").trim().toLowerCase();
      const password = body.password || "";

      if (!orgName || !orgSlug || !adminName || !adminEmail || !password) {
        return json({
          success: false,
          error: "Tous les champs sont requis"
        }, 400);
      }

      const slugOk = /^[a-z0-9-]{3,40}$/.test(orgSlug);
      if (!slugOk) {
        return json({
          success: false,
          error: "Le slug doit contenir seulement lettres minuscules, chiffres et tirets"
        }, 400);
      }

      if (password.length < 8) {
        return json({
          success: false,
          error: "Le mot de passe doit contenir au moins 8 caractères"
        }, 400);
      }

      const passwordHash = await derivePasswordHash(password);

      const orgInsert = await env.DB.prepare(`
        INSERT INTO organizations (name, slug, description, logo_url)
        VALUES (?, ?, ?, ?)
      `).bind(orgName, orgSlug, "Organisation principale", "").run();

      const organizationId = orgInsert.meta.last_row_id;

      const userInsert = await env.DB.prepare(`
        INSERT INTO users (organization_id, name, email, password_hash, role, department, is_active)
        VALUES (?, ?, ?, ?, 'superadmin', 'Direction', 1)
      `).bind(
        organizationId,
        adminName,
        adminEmail,
        passwordHash.full
      ).run();

      const userId = userInsert.meta.last_row_id;

      await logActivity(env, organizationId, userId, "bootstrap", "Initialisation du portail");

      const token = await createSessionToken({ userId }, env.JWT_SECRET);

      return json({
        success: true,
        message: "Initialisation réussie"
      }, 200, {
        "Set-Cookie": makeSetCookie(SESSION_COOKIE, token, SESSION_TTL_SECONDS)
      });
    }

    // Login
    if (request.method === "POST" && url.pathname === "/api/login") {
      const body = await readJson(request);
      if (!body) {
        return json({ success: false, error: "JSON invalide" }, 400);
      }

      const organizationSlug = (body.organization || "").trim().toLowerCase();
      const email = (body.email || "").trim().toLowerCase();
      const password = body.password || "";

      if (!organizationSlug || !email || !password) {
        return json({
          success: false,
          error: "Organisation, email et mot de passe requis"
        }, 400);
      }

      const user = await env.DB.prepare(`
        SELECT
          u.id,
          u.organization_id,
          u.name,
          u.email,
          u.password_hash,
          u.role,
          u.department,
          u.is_active,
          o.name AS organization_name,
          o.slug AS organization_slug
        FROM users u
        JOIN organizations o ON o.id = u.organization_id
        WHERE o.slug = ? AND u.email = ?
        LIMIT 1
      `).bind(organizationSlug, email).first();

      if (!user || Number(user.is_active) !== 1) {
        return json({
          success: false,
          error: "Identifiants invalides"
        }, 401);
      }

      const passwordOk = await verifyPassword(password, user.password_hash);
      if (!passwordOk) {
        return json({
          success: false,
          error: "Identifiants invalides"
        }, 401);
      }

      const token = await createSessionToken({ userId: user.id }, env.JWT_SECRET);

      await logActivity(env, user.organization_id, user.id, "login", "Connexion réussie");

      return json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          department: user.department,
          organization_id: user.organization_id,
          organization_name: user.organization_name,
          organization_slug: user.organization_slug
        }
      }, 200, {
        "Set-Cookie": makeSetCookie(SESSION_COOKIE, token, SESSION_TTL_SECONDS)
      });
    }

    // Logout
    if (request.method === "POST" && url.pathname === "/api/logout") {
      return json({
        success: true,
        message: "Déconnecté"
      }, 200, {
        "Set-Cookie": clearCookie(SESSION_COOKIE)
      });
    }

    // Me
    if (request.method === "GET" && url.pathname === "/api/me") {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.error;

      const user = auth.user;

      const usersCountRow = await env.DB.prepare(`
        SELECT COUNT(*) AS count FROM users WHERE organization_id = ?
      `).bind(user.organization_id).first();

      const projectsCountRow = await env.DB.prepare(`
        SELECT COUNT(*) AS count FROM projects WHERE organization_id = ?
      `).bind(user.organization_id).first();

      return json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          department: user.department
        },
        organization: {
          id: user.organization_id,
          name: user.organization_name,
          slug: user.organization_slug,
          description: user.organization_description,
          logo_url: user.organization_logo
        },
        stats: {
          users: Number(usersCountRow?.count || 0),
          projects: Number(projectsCountRow?.count || 0)
        }
      });
    }

    // Projects list
    if (request.method === "GET" && url.pathname === "/api/projects") {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.error;

      const user = auth.user;

      const projects = await env.DB.prepare(`
        SELECT
          p.id,
          p.name,
          p.description,
          p.status,
          p.created_at,
          owner.name AS owner_name
        FROM projects p
        LEFT JOIN users owner ON owner.id = p.owner_user_id
        WHERE p.organization_id = ?
        ORDER BY p.created_at DESC
      `).bind(user.organization_id).all();

      return json({
        success: true,
        projects: projects.results || []
      });
    }

    // Admin users list
    if (request.method === "GET" && url.pathname === "/api/admin/users") {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.error;

      if (!canManageUsers(auth.user.role)) {
        return json({ success: false, error: "Accès refusé" }, 403);
      }

      let sql = `
        SELECT
          u.id,
          u.name,
          u.email,
          u.role,
          u.department,
          u.is_active,
          u.created_at,
          o.name AS organization_name,
          o.slug AS organization_slug
        FROM users u
        JOIN organizations o ON o.id = u.organization_id
      `;
      let query;

      if (isSuperAdmin(auth.user.role)) {
        sql += ` ORDER BY o.name, u.name`;
        query = await env.DB.prepare(sql).all();
      } else {
        sql += ` WHERE u.organization_id = ? ORDER BY u.name`;
        query = await env.DB.prepare(sql).bind(auth.user.organization_id).all();
      }

      return json({
        success: true,
        users: query.results || []
      });
    }

    // Admin create user
    if (request.method === "POST" && url.pathname === "/api/admin/users") {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.error;

      if (!canManageUsers(auth.user.role)) {
        return json({ success: false, error: "Accès refusé" }, 403);
      }

      const body = await readJson(request);
      if (!body) return json({ success: false, error: "JSON invalide" }, 400);

      const name = (body.name || "").trim();
      const email = (body.email || "").trim().toLowerCase();
      const password = body.password || "";
      const department = (body.department || "").trim();
      const role = normalizeRole(body.role || "user");

      let organizationId = auth.user.organization_id;
      if (isSuperAdmin(auth.user.role) && body.organization_id) {
        organizationId = Number(body.organization_id);
      }

      if (!name || !email || !password) {
        return json({ success: false, error: "Nom, email et mot de passe requis" }, 400);
      }

      if (password.length < 8) {
        return json({ success: false, error: "Mot de passe trop court" }, 400);
      }

      if (!isSuperAdmin(auth.user.role) && role === "superadmin") {
        return json({ success: false, error: "Impossible de créer un superadmin" }, 403);
      }

      const passwordHash = await derivePasswordHash(password);

      try {
        await env.DB.prepare(`
          INSERT INTO users (organization_id, name, email, password_hash, role, department, is_active)
          VALUES (?, ?, ?, ?, ?, ?, 1)
        `).bind(
          organizationId,
          name,
          email,
          passwordHash.full,
          role,
          department
        ).run();

        await logActivity(env, organizationId, auth.user.id, "create_user", `${email} (${role})`);

        return json({
          success: true,
          message: "Utilisateur créé"
        });
      } catch (error) {
        return json({
          success: false,
          error: "Impossible de créer l'utilisateur. Email déjà utilisé ?"
        }, 400);
      }
    }

    // Admin organizations list
    if (request.method === "GET" && url.pathname === "/api/admin/organizations") {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.error;

      if (!isSuperAdmin(auth.user.role)) {
        return json({ success: false, error: "Accès refusé" }, 403);
      }

      const orgs = await env.DB.prepare(`
        SELECT
          o.id,
          o.name,
          o.slug,
          o.description,
          o.logo_url,
          o.created_at,
          (SELECT COUNT(*) FROM users u WHERE u.organization_id = o.id) AS users_count,
          (SELECT COUNT(*) FROM projects p WHERE p.organization_id = o.id) AS projects_count
        FROM organizations o
        ORDER BY o.name
      `).all();

      return json({
        success: true,
        organizations: orgs.results || []
      });
    }

    // Admin create organization
    if (request.method === "POST" && url.pathname === "/api/admin/organizations") {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.error;

      if (!isSuperAdmin(auth.user.role)) {
        return json({ success: false, error: "Accès refusé" }, 403);
      }

      const body = await readJson(request);
      if (!body) return json({ success: false, error: "JSON invalide" }, 400);

      const name = (body.name || "").trim();
      const slug = (body.slug || "").trim().toLowerCase();
      const description = (body.description || "").trim();
      const logo_url = (body.logo_url || "").trim();

      if (!name || !slug) {
        return json({ success: false, error: "Nom et slug requis" }, 400);
      }

      if (!/^[a-z0-9-]{3,40}$/.test(slug)) {
        return json({ success: false, error: "Slug invalide" }, 400);
      }

      try {
        await env.DB.prepare(`
          INSERT INTO organizations (name, slug, description, logo_url)
          VALUES (?, ?, ?, ?)
        `).bind(name, slug, description, logo_url).run();

        await logActivity(env, null, auth.user.id, "create_organization", `${name} (${slug})`);

        return json({
          success: true,
          message: "Organisation créée"
        });
      } catch {
        return json({
          success: false,
          error: "Impossible de créer l'organisation. Slug déjà utilisé ?"
        }, 400);
      }
    }

    // Admin create project
    if (request.method === "POST" && url.pathname === "/api/admin/projects") {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.error;

      if (!canManageProjects(auth.user.role)) {
        return json({ success: false, error: "Accès refusé" }, 403);
      }

      const body = await readJson(request);
      if (!body) return json({ success: false, error: "JSON invalide" }, 400);

      const name = (body.name || "").trim();
      const description = (body.description || "").trim();
      const status = (body.status || "active").trim();

      let organizationId = auth.user.organization_id;
      if (isSuperAdmin(auth.user.role) && body.organization_id) {
        organizationId = Number(body.organization_id);
      }

      if (!name) {
        return json({ success: false, error: "Nom du projet requis" }, 400);
      }

      await env.DB.prepare(`
        INSERT INTO projects (organization_id, name, description, status, owner_user_id)
        VALUES (?, ?, ?, ?, ?)
      `).bind(
        organizationId,
        name,
        description,
        status,
        auth.user.id
      ).run();

      await logActivity(env, organizationId, auth.user.id, "create_project", name);

      return json({
        success: true,
        message: "Projet créé"
      });
    }

    return json({ success: false, error: "Not Found" }, 404);
  }
};
