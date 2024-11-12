import { Hono } from "hono";
import { generateJWT, pemToJwk, verifyJWT } from "../utils/jwk_converter";
import { SecretsManager } from "../libs/secrets";
import { db } from "../db";
import crypto from "node:crypto";
import { v4 as uuid } from "uuid";
import { LoginPageController } from "./render";

const app = new Hono();
  

const CryptoKeys = SecretsManager.init();
const BASE_URL = "http://localhost:4000/oidc";

// OIDC Endpoints
app.get("/oidc/.well-known/jwks.json", async (ctx) => {
    const jwks = await pemToJwk(CryptoKeys.publicKey);

    return ctx.json({
        keys: [
            jwks
        ]
    })
});

app.get("/oidc/.well-known/openid-configuration", async (ctx) => {
    return ctx.json({
        issuer: BASE_URL,
        authorization_endpoint: BASE_URL + "/authorize",
        token_endpoint: BASE_URL + "/token",
        userinfo_endpoint: BASE_URL + "/userinfo",
        introspection_endpoint: BASE_URL + "/introspect",
        end_session_endpoint: BASE_URL + "/logout",
        revocation_endpoint: BASE_URL + "/revoke",
        jwks_uri: BASE_URL + "/.well-known/jwks.json",
        response_modes_supported: [
            "query",
            "fragment",
            "form_post"
        ],
        token_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post"
        ],
        token_endpoint_auth_signing_alg_values_supported: [
            "RS256"
        ],
        introspection_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post"
        ],
        introspection_endpoint_auth_signing_alg_values_supported: [
            "RS256"
        ],
        revocation_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post"
        ],
        revocation_endpoint_auth_signing_alg_values_supported: [
            "RS256"
        ],
        response_types_supported: [
            "code",
        ],
        grant_types_supported: [
            "authorization_code",
            "refresh_token"
        ],
        subject_types_supported: [
            "public"
        ],
        userinfo_signing_alg_values_supported: [
            "RS256"
        ],
        id_token_signing_alg_values_supported: [
            "RS256"
        ],
        scopes_supported: [
            "openid",
            "profile",
            "email"
        ],
        claims_supported: [
            "id",
            "name",
            "email",
            "email_verified",
            "picture"
        ],
        code_challenge_methods_supported: [
            "S256"
        ],
        request_parameter_supported: true,
        request_uri_parameter_supported: true,
        require_request_uri_registration: true,
    })
});

app.get("/oidc/authorize", LoginPageController)

app.post("/oidc/authorize", async (ctx) => {
    const {
        client_id,
        redirect_uri,
        response_type,
        scope,
        state,
        email,
        password
    } : {
        client_id: string,
        redirect_uri: string,
        response_type: string,
        scope: string,
        state: string,
        email: string,
        password: string
    } = await ctx.req.parseBody();

    if (!client_id || !redirect_uri || !response_type || !scope) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    // Check if client exists
    const client = await db
        .prepare("SELECT * FROM clients WHERE id = ?")
        .get(client_id) as {
            id: string,
            name: string,
            secret: string,
            redirect_uri: string,
            created_at: string,
            updated_at: string
        }

    if (!client) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client not found"
        }, 400)
    }

    // Check if redirect_uri is valid
    if (client.redirect_uri !== redirect_uri) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Invalid redirect_uri"
        }, 400)
    }

    // Check if response_type is valid
    if (response_type !== "code") {
        return ctx.json({
            error: "unsupported_response_type",
            error_description: "Response type not supported"
        }, 400)
    }

    // Check if scope is valid
    let scopes;
    let scopesSpace = scope.split(" ");
    let scopesComma = scope.split(",");
    let scopesPipe = scope.split("+");
    
    if (scopesSpace.length > 1) {
        scopes = scopesSpace;
    }
    else if (scopesComma.length > 1) {
        scopes = scopesComma;
    }
    else if (scopesPipe.length > 1) {
        scopes = scopesPipe;
    }
    else {
        scopes = [scope];
    }

    console.log(scopes)

    const validScopes = db
        .prepare("SELECT * FROM scopes WHERE client_id = ?")
        .all(client_id) as {
            id: string,
            name: string,
            client_id: string,
            created_at: string,
            updated_at: string
        }[]

    const validScopeNames = validScopes.map(scope => scope.name);
    const invalidScopes = scopes.filter((scope: string) => !validScopeNames.includes(scope));

    if (invalidScopes.length > 0) {
        return ctx.json({
            error: "invalid_scope",
            error_description: "Invalid scope"
        }, 400)
    }

    // Check if user exists
    const user = await db
        .prepare("SELECT * FROM users WHERE email = ?")
        .get(email) as {
            id: string,
            first_name: string,
            last_name: string,
            email: string,
            password: string,
            avatar_url: string,
            created_at: string,
            updated_at: string
        }

    const passwordHash = crypto
        .createHash("sha256")
        .update(password)
        .digest("hex")

    // Check if password is valid
    if (!user || user.password !== passwordHash) {
        return ctx.json({
            error: "invalid_grant",
            error_description: "Invalid credentials"
        }, 400)
    }

    // Generate authorization code
    const code = crypto.randomBytes(16).toString("hex");
    const created_at = new Date().toISOString();

    // Store authorization code
    const stmt = db.prepare(`
        INSERT INTO authorization_codes (id, code, user_id, client_id, scopes, state, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)

    if (state) {
        stmt.run(uuid(), code, user.id, client_id, scopes.join(" "), state, created_at, created_at)
    }

    else {
        stmt.run(uuid(), code, user.id, client_id, scopes.join(" "), "", created_at, created_at)
    }

    return ctx.redirect(redirect_uri + `?code=${code}&state=${state}`)
});

app.post("/oidc/token", async (ctx) => {
    const { client_id, client_secret, grant_type, code, redirect_uri } : {
        client_id: string,
        client_secret: string,
        grant_type: string,
        code: string,
        redirect_uri: string
    } = await ctx.req.parseBody();

    if (!client_id || !client_secret || !grant_type || !code || !redirect_uri) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    // Check if client exists
    const client = await db
        .prepare("SELECT * FROM clients WHERE id = ?")
        .get(client_id) as {
            id: string,
            name: string,
            secret: string,
            redirect_uri: string,
            created_at: string,
            updated_at: string
        }

    if (!client) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client not found"
        }, 400)
    }

    // Check if client_secret is valid
    if (client.secret !== client_secret) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client secret is invalid"
        }, 400)
    }

    // Check if grant_type is valid
    if (grant_type !== "authorization_code") {
        return ctx.json({
            error: "unsupported_grant_type",
            error_description: "Grant type not supported"
        }, 400)
    }

    // Check if code is valid
    const authorization_code = await db
        .prepare("SELECT * FROM authorization_codes WHERE code = ?")
        .get(code) as {
            id: string,
            code: string,
            user_id: string,
            client_id: string,
            scopes: string,
            state: string,
            created_at: string,
            updated_at: string
        }

    if (!authorization_code) {
        return ctx.json({
            error: "invalid_grant",
            error_description: "Authorization code not found"
        }, 400)
    }

    // Check if client_id matches
    if (authorization_code.client_id !== client_id) {
        return ctx.json({
            error: "invalid_grant",
            error_description: "Client ID does not match"
        }, 400)
    }
    
    // Generate access token
    const access_token = await generateJWT(
        {
            sub: authorization_code.user_id,
            scope: authorization_code.scopes
        }, CryptoKeys.privateKey
    );
    const refresh_token = "rft_" + crypto.randomBytes(32).toString("hex");

    // Store session
    const stmt = db.prepare(`
        INSERT INTO sessions (id, user_id, client_id, refresh_token, scopes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `)

    stmt.run(uuid(), authorization_code.user_id, client_id, refresh_token, authorization_code.scopes,new Date().toISOString(), new Date().toISOString())

    // Return tokens
    return ctx.json({
        access_token,
        token_type: "bearer",
        expires_in: 3600,
        refresh_token
    })
});

app.post("/oidc/token/refresh", async (ctx) => {
    const { client_id, client_secret, grant_type, refresh_token } = await ctx.req.json();

    if (!client_id || !client_secret || !grant_type || !refresh_token) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    // Check if client exists
    const client = await db
        .prepare("SELECT * FROM clients WHERE id = ?")
        .get(client_id) as {
            id: string,
            name: string,
            secret: string,
            redirect_uri: string,
            created_at: string,
            updated_at: string
        }

    if (!client) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client not found"
        }, 400)
    }

    // Check if client_secret is valid
    if (client.secret !== client_secret) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client secret is invalid"
        }, 400)
    }

    // Check if grant_type is valid
    if (grant_type !== "refresh_token") {
        return ctx.json({
            error: "unsupported_grant_type",
            error_description: "Grant type not supported"
        }, 400)
    }

    // Find session by refresh token
    const session = await db
        .prepare("SELECT * FROM sessions WHERE refresh_token = ?")
        .get(refresh_token) as {
            id: string,
            user_id: string,
            client_id: string,
            refresh_token: string,
            scopes: string,
            created_at: string,
            updated_at: string
        }

    if (!session) {
        return ctx.json({
            error: "invalid_grant",
            error_description: "Refresh token not found"
        }, 400)
    }

    // Generate access token
    const access_token = await generateJWT(
        {
            sub: session.user_id,
            scope: session.scopes
        }, CryptoKeys.privateKey
    );

    // Return tokens
    return ctx.json({
        access_token,
        token_type: "bearer",
        expires_in: 3600
    })
});

app.post("/oidc/introspect", async (ctx) => {
    const { client_id, client_secret, token } = await ctx.req.json();

    if (!client_id || !client_secret || !token) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    // Check if client exists
    const client = await db
        .prepare("SELECT * FROM clients WHERE id = ?")
        .get(client_id) as {
            id: string,
            name: string,
            secret: string,
            redirect_uri: string,
            created_at: string,
            updated_at: string
        }

    if (!client) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client not found"
        }, 400)
    }

    // Check if client_secret is valid
    if (client.secret !== client_secret) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client secret is invalid"
        }, 400)
    }

    const token_data = await verifyJWT(token, CryptoKeys.publicKey);

    // Check if token is valid
    const session = await db
        .prepare("SELECT * FROM sessions WHERE user_id = ?")
        .get(token_data.payload.sub!) as {
            id: string,
            user_id: string,
            client_id: string,
            created_at: string,
            updated_at: string
        }

    if (!session) {
        return ctx.json({
            active: false
        })
    }

    // Return session
    return ctx.json({
        active: true,
        client_id: session.client_id,
        user_id: session.user_id
    })
});

app.post("/oidc/revoke", async (ctx) => {
    const { client_id, client_secret, token } = await ctx.req.json();

    if (!client_id || !client_secret || !token) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    // Check if client exists
    const client = await db
        .prepare("SELECT * FROM clients WHERE id = ?")
        .get(client_id) as {
            id: string,
            name: string,
            secret: string,
            redirect_uri: string,
            created_at: string,
            updated_at: string
        }

    if (!client) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client not found"
        }, 400)
    }

    // Check if client_secret is valid
    if (client.secret !== client_secret) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client secret is invalid"
        }, 400)
    }

    // Check if token is valid
    const session = await db
        .prepare("SELECT * FROM sessions WHERE refresh_token = ?")
        .get(token) as {
            id: string,
            user_id: string,
            client_id: string,
            refresh_token: string,
            scopes: string,
            created_at: string,
            updated_at: string
        }

    if (!session) {
        return ctx.json({
            error: "invalid_token",
            error_description: "Token not found"
        }, 400)
    }

    // Delete session
    db.prepare("DELETE FROM sessions WHERE refresh_token = ?").run(token)

    // Return success
    return ctx.json({
        success: true
    })
});

app.post("/oidc/userinfo", async (ctx) => {
    const { client_id, client_secret, token } = await ctx.req.json();

    if (!client_id || !client_secret || !token) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    // Check if client exists
    const client = await db
        .prepare("SELECT * FROM clients WHERE id = ?")
        .get(client_id) as {
            id: string,
            name: string,
            secret: string,
            redirect_uri: string,
            created_at: string,
            updated_at: string
        }

    if (!client) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client not found"
        }, 400)
    }

    // Check if client_secret is valid
    if (client.secret !== client_secret) {
        return ctx.json({
            error: "invalid_client",
            error_description: "Client secret is invalid"
        }, 400)
    }

    const token_data = await verifyJWT(token, CryptoKeys.publicKey);

    // Check if token is valid
    const session = await db
        .prepare("SELECT * FROM sessions WHERE user_id = ?")
        .get(token_data.payload.sub!) as {
            id: string,
            user_id: string,
            client_id: string,
            refresh_token: string,
            scopes: string,
            created_at: string,
            updated_at: string
        }

    if (!session) {
        return ctx.json({
            error: "invalid_token",
            error_description: "Token not found"
        }, 400)
    }

    // Check if user exists
    const user = await db
        .prepare("SELECT * FROM users WHERE id = ?")
        .get(session.user_id) as {
            id: string,
            first_name: string,
            last_name: string,
            email: string,
            avatar_url: string,
            created_at: string,
            updated_at: string
        }

    if (!user) {
        return ctx.json({
            error: "invalid_token",
            error_description: "User not found"
        }, 400)
    }

    // Return user info
    return ctx.json({
        sub: user.id,
        name: `${user.first_name} ${user.last_name}`,
        email: user.email,
        picture: user.avatar_url
    })
});

// Client Endpoints
app.post("/clients", async (ctx) => {
    const { name, redirect_uri } = await ctx.req.json()

    if (!name || !redirect_uri) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    const id = uuid();
    const secret = crypto.randomBytes(32).toString("hex");
    const created_at = new Date().toISOString();

    const stmt = db.prepare(`
        INSERT INTO clients (id, name, secret, redirect_uri, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `)

    stmt.run(id, name, secret, redirect_uri, created_at, created_at)

    return ctx.json({
        id,
        secret
    })
})
app.get("/clients", async (ctx) => {
    const clients = db.prepare("SELECT * FROM clients").all();

    return ctx.json(clients)
})
app.get("/clients/:id", async (ctx) => {
    const client = db.prepare("SELECT * FROM clients WHERE id = ?").get(ctx.req.param('id'));

    if (!client) {
        return ctx.json({
            error: "not_found",
            error_description: "Client not found"
        }, 404)
    }

    return ctx.json(client)
})
app.put("/clients/:id", async (ctx) => {
    const { name, redirect_uri } = await ctx.req.json()

    if (!name || !redirect_uri) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    const client = db
        .prepare("SELECT * FROM clients WHERE id = ?")
        .get(ctx.req.param('id')) as {
            id: string,
            name: string,
            secret: string,
            redirect_uri: string,
            created_at: string,
            updated_at: string
        }

    if (!client) {
        return ctx.json({
            error: "not_found",
            error_description: "Client not found"
        }, 404)
    }

    db.prepare("UPDATE clients SET name = ?, redirect_uri = ?, updated_at = ? WHERE id = ?").run(name, redirect_uri, new Date().toISOString(), client.id)

    return ctx.json({
        success: true
    })
})
app.delete("/clients/:id", async (ctx) => {
    const client = db.prepare("SELECT * FROM clients WHERE id = ?").get(ctx.req.param('id')) as {
        id: string,
    };

    if (!client) {
        return ctx.json({
            error: "not_found",
            error_description: "Client not found"
        }, 404)
    }

    db.prepare("DELETE FROM clients WHERE id = ?").run(client.id)

    return ctx.json({
        success: true
    })
})

// User Endpoints
app.post("/users", async (ctx) => {
    const { first_name, last_name, email, password, avatar_url } = await ctx.req.json()

    if (!first_name || !last_name || !email || !password) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    const id = uuid();
    const passwordHash = crypto
        .createHash("sha256")
        .update(password)
        .digest("hex")
    const created_at = new Date().toISOString();

    const stmt = db.prepare(`
        INSERT INTO users (id, first_name, last_name, email, password, avatar_url, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)

    stmt.run(id, first_name, last_name, email, passwordHash, avatar_url, created_at, created_at)

    return ctx.json({
        id
    })
})
app.get("/users", async (ctx) => {
    const users = db.prepare("SELECT * FROM users").all();

    return ctx.json(users)
})
app.get("/users/:id", async (ctx) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(ctx.req.param('id'));

    if (!user) {
        return ctx.json({
            error: "not_found",
            error_description: "User not found"
        }, 404)
    }

    return ctx.json(user)
})
app.put("/users/:id", async (ctx) => {
    const { first_name, last_name, email, password, avatar_url } = await ctx.req.json()

    if (!first_name || !last_name || !email || !password) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    const user = db
        .prepare("SELECT * FROM users WHERE id = ?")
        .get(ctx.req.param('id')) as {
            id: string,
            first_name: string,
            last_name: string,
            email: string,
            password: string,
            avatar_url: string,
            created_at: string,
            updated_at: string
        }

    if (!user) {
        return ctx.json({
            error: "not_found",
            error_description: "User not found"
        }, 404)
    }

    const passwordHash = crypto
        .createHash("sha256")
        .update(password)
        .digest("hex")

    db.prepare("UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, avatar_url = ?, updated_at = ? WHERE id = ?").run(first_name, last_name, email, passwordHash, avatar_url, new Date().toISOString(), user.id)

    return ctx.json({
        success: true
    })
})
app.delete("/users/:id", async (ctx) => {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(ctx.req.param('id')) as {
        id: string,
    };

    if (!user) {
        return ctx.json({
            error: "not_found",
            error_description: "User not found"
        }, 404)
    }

    db.prepare("DELETE FROM users WHERE id = ?").run(user.id)

    return ctx.json({
        success: true
    })
})

// Scope Endpoints
app.get("/scopes/:client_id", async (ctx) => {
    const scopes = db.prepare("SELECT * FROM scopes WHERE client_id = ?").all(ctx.req.param('client_id'));

    return ctx.json(scopes)
})
app.post("/scopes/:client_id", async (ctx) => {
    const { name } = await ctx.req.json()

    if (!name) {
        return ctx.json({
            error: "invalid_request",
            error_description: "Missing required parameters"
        }, 400)
    }

    const id = uuid();
    const created_at = new Date().toISOString();

    const stmt = db.prepare(`
        INSERT INTO scopes (id, name, client_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
    `)

    stmt.run(id, name, ctx.req.param('client_id'), created_at, created_at)

    return ctx.json({
        id
    })
})
app.delete("/scopes/:id", async (ctx) => {
    const scope = db.prepare("SELECT * FROM scopes WHERE id = ?").get(ctx.req.param('id')) as {
        id: string,
    };

    if (!scope) {
        return ctx.json({
            error: "not_found",
            error_description: "Scope not found"
        }, 404)
    }

    db.prepare("DELETE FROM scopes WHERE id = ?").run(scope.id)

    return ctx.json({
        success: true
    })
})

// Generics
app.get("/health", async (ctx) => {
    return ctx.json({
        status: "ok"
    })
})
app.get("/version", async (ctx) => {
    return ctx.json({
        version: "0.0.0"
    })
})

export default app;
