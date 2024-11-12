import * as client from "openid-client"
import { Hono } from "hono"
import { logger } from "hono/logger"
import { showRoutes } from "hono/dev"

await new Promise((resolve) => setTimeout(resolve, 2000))

let redirect_uri!: string
let scope!: string // Scope of the access request
let code_verifier: string = client.randomPKCECodeVerifier()
let code_challenge: string =
  await client.calculatePKCECodeChallenge(code_verifier)
let state!: string

let clientAuth!: client.ClientAuth | undefined

let parameters: Record<string, string> = {
  redirect_uri: "http://localhost:3000/callback",
  scope: "openid email",
  code_challenge,
  code_challenge_method: 'S256',
}

export const createClient = async (issuer: string, client_id: string, client_secret: string) => {
    let config : client.Configuration = await client.discovery(
        new URL(issuer),
        client_id,
        client_secret,
        clientAuth,
        {
            execute: [client.allowInsecureRequests],
        }
    )

    return config
}

const config = await createClient(
    "http://localhost:4000/oidc",
    "77010371-3ea3-4cac-b2ba-89a6b9440c07",
    "676fe515d7a79d9599723056a272149775e2557cf1207f782842cde09f0c575c",
)

if (!config.serverMetadata().supportsPKCE()) {
  /**
   * We cannot be sure the server supports PKCE so we're going to use state too.
   * Use of PKCE is backwards compatible even if the AS doesn't support it which
   * is why we're using it regardless. Like PKCE, random state must be generated
   * for every redirect to the authorization_endpoint.
   */
  state = client.randomState()
  parameters.state = state
}

const app = new Hono()

app.use(logger())

app.get("/auth", async (ctx) => {
    let redirectTo: URL = client.buildAuthorizationUrl(config, parameters)
    return ctx.redirect(redirectTo.href)
})

app.get("/callback", async (ctx) => {
    const { code, state } = ctx.req.query()
    let tokenSet = await client.genericGrantRequest(config, "authorization_code", {
        code,
        redirect_uri: parameters.redirect_uri,
    })

    return ctx.json(tokenSet)
})

showRoutes(app)

export default {
    port: 3000,
    fetch: app.fetch,
}