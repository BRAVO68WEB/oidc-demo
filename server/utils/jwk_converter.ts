import * as jose from 'jose'

export const pemToJwk = async (pem: string) => {
    let rsaPubKey = await jose.importSPKI(pem, 'RS512', {
        extractable: true,
    });
    
    return jose.exportJWK(rsaPubKey);
}

export const jwkToPem = async (jwk: jose.JWK) => {
    let rsaPubKey = await jose.importJWK(jwk, 'RS512');
    
    return jose.exportSPKI(rsaPubKey as jose.KeyLike);
}

export const generateJWT = async (payload: {
    sub: string,
    scope: string
}, privateKey: string) => {
    let rsaPrivKey = await jose.importPKCS8(privateKey, 'RS512', {
        extractable: true,
    });

    return await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: 'RS512' })
        .setIssuer('http://localhost:4000/oidc')
        .setIssuedAt()
        .setSubject(payload.sub)
        .setExpirationTime('6h')
        .sign(rsaPrivKey);
}

export const verifyJWT = async (token: string, publicKey: string) => {
    let rsaPubKey = await jose.importSPKI(publicKey, 'RS512', {
        extractable: true,
    });

    return await jose.jwtVerify(token, rsaPubKey, {
        issuer: 'http://localhost:4000/oidc',
        algorithms: ['RS512']
    });
}