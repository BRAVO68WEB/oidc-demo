import { Hono } from "hono";
import { SecretsManager } from "./libs/secrets";
import { pemToJwk } from "./utils/jwk_converter";

const CryptoKeys = SecretsManager.init();

const app = new Hono();

app.get("/", async (ctx) => {
    return ctx.json({
        message: "Hello, World!"
    })
});

app.get("/.well-known/jwks.json", async (ctx) => {
    const jwks = await pemToJwk(CryptoKeys.publicKey);

    return ctx.json({
        keys: [
            jwks
        ]
    })
});

export default {
    port: 4000,
    fetch: app.fetch,
};