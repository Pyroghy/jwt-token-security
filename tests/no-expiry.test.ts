import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { app as fixedApp } from "../src/server/fixed.ts";
import { app as vulnerableApp } from "../src/server/vulnerable.ts";
import type { JwtPayload } from "../src/utils/types.ts";
import { login, me, withServer } from "./helpers.ts";

// Reads the exp claim from a token.
function expSeconds(token: string): number {
    const parts = token.split(".");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as JwtPayload;

    if (payload.exp === undefined) {
        return 0;
    }

    return payload.exp;
}

// Waits until the token's exp time has passed.
async function waitUntilExpired(token: string): Promise<void> {
    const waitMs = expSeconds(token) * 1000 - Date.now() + 1100;

    if (waitMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
}

describe("no expiry", () => {
    it("vulnerable server accepts a token after it expires", async () => {
        await withServer(vulnerableApp, async (baseUrl) => {
            const token = await login(baseUrl, 1);
            const before = await me(baseUrl, token);

            assert.equal(before.status, 200);

            await waitUntilExpired(token);

            assert.ok(expSeconds(token) < Date.now() / 1000);

            const after = await me(baseUrl, token);

            assert.equal(after.status, 200);
        });
    });

    it("fixed server rejects a token after it expires", async () => {
        await withServer(fixedApp, async (baseUrl) => {
            const fresh = await login(baseUrl);
            const freshResponse = await me(baseUrl, fresh);

            assert.equal(freshResponse.status, 200);

            const token = await login(baseUrl, 1);

            await waitUntilExpired(token);

            assert.ok(expSeconds(token) < Date.now() / 1000);

            const response = await me(baseUrl, token);

            assert.equal(response.status, 401);
        });
    });
});
