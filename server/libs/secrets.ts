import { readFileSync } from 'node:fs';

export class SecretsManager {
	static init() {
		const privateKey = readFileSync(".keys/priv-key.pem", 'utf8');
		const publicKey = readFileSync(".keys/pub-key.pem", 'utf8');

        return {
            privateKey,
            publicKey
        };
	}
}