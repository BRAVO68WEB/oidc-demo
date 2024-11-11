import * as jose from 'jose'

export const pemToJwk = async (pem: string) => {
    let rsaPubKey = await jose.importSPKI(pem, 'ES256', {
        extractable: true,
    });
    
    return jose.exportJWK(rsaPubKey);
}