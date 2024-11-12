import { Hono } from "hono";
import { LoginPageController } from "./render";

import { WellKnownController } from "../controllers/well-known.controller";
import { OIDC } from "../controllers/oidc.controller";
import { Clients } from "../controllers/clients.controller";
import { Users } from "../controllers/users.controller";
import { MetaController } from "../controllers/meta.controller";
import { Scopes } from "../controllers/scopes.controller";

const app = new Hono();

// OIDC Endpoints
app.get("/oidc/.well-known/jwks.json", WellKnownController.JWKS);
app.get("/oidc/.well-known/openid-configuration", WellKnownController.OpenIDConfig);
app.get("/oidc/authorize", LoginPageController)
app.post("/oidc/authorize", OIDC.Authorize);
app.post("/oidc/token", OIDC.Token);
app.post("/oidc/token/refresh", OIDC.Refresh);
app.post("/oidc/introspect", OIDC.Introspect);
app.post("/oidc/revoke", OIDC.Revoke);
app.post("/oidc/userinfo", OIDC.UserInfo);

// Client Endpoints
app.post("/clients", Clients.CreateClients)
app.get("/clients", Clients.GetClients)
app.get("/clients/:id", Clients.GetClient)
app.put("/clients/:id", Clients.UpdateClient)
app.delete("/clients/:id", Clients.DeleteClient)

// User Endpoints
app.post("/users", Users.CreateUser)
app.get("/users", Users.GetUsers)
app.get("/users/:id", Users.GetUser)
app.put("/users/:id", Users.UpdateUser)
app.delete("/users/:id", Users.DeleteUser)

// Scope Endpoints
app.get("/scopes/:client_id", Scopes.GetScopes)
app.post("/scopes/:client_id", Scopes.CreateScope)
app.delete("/scopes/:id", Scopes.DeleteScope)

// Generics
app.get("/health", MetaController.Health)
app.get("/version", MetaController.Version)

export default app;
