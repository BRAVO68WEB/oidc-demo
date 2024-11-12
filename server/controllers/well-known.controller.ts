import type { Context } from "hono";

import { Config } from "../utils/config";
import { SecretsManager } from "../libs/secrets";
import { pemToJwk } from "../utils/jwk_converter";

const CryptoKeys = SecretsManager.init();

export class WellKnownController {
    public static readonly JWKS = async (ctx: Context) => {
        const jwks = await pemToJwk(CryptoKeys.publicKey);

        return ctx.json({
            keys: [
                jwks
            ]
        })
    };

    public static readonly OpenIDConfig = (ctx: Context) => {
        return ctx.json({
            issuer: Config.BASE_URL,
            authorization_endpoint: Config.BASE_URL + "/authorize",
            token_endpoint: Config.BASE_URL + "/token",
            userinfo_endpoint: Config.BASE_URL + "/userinfo",
            introspection_endpoint: Config.BASE_URL + "/introspect",
            end_session_endpoint: Config.BASE_URL + "/logout",
            revocation_endpoint: Config.BASE_URL + "/revoke",
            jwks_uri: Config.BASE_URL + "/.well-known/jwks.json",
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
    };
}