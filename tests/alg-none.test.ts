import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { app as fixedApp } from "../src/server/fixed.ts";
import { app as vulnerableApp } from "../src/server/vulnerable.ts";
import type { JwtHeader, JwtPayload, TokenUser } from "../src/utils/types.ts";
import { me, withServer } from "./helpers.ts";

// Builds an unsigned admin token with alg none.
function noneToken(): string {
    const headerBody: JwtHeader = { alg: "none", typ: "JWT" };
    const payloadBody: JwtPayload = {
        username: "admin",
        role: "admin",
        exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const header = Buffer.from(JSON.stringify(headerBody)).toString("base64url");
    const payload = Buffer.from(JSON.stringify(payloadBody)).toString("base64url");

    return `${header}.${payload}.`;
}

describe("alg none", () => {
    it("vulnerable server accepts an unsigned admin token", async () => {
        await withServer(vulnerableApp, async (baseUrl) => {
            const response = await me(baseUrl, noneToken());

            assert.equal(response.status, 200);

            const body = (await response.json()) as TokenUser;

            assert.equal(body.role, "admin");
        });
    });

    it("fixed server rejects an unsigned admin token", async () => {
        await withServer(fixedApp, async (baseUrl) => {
            const response = await me(baseUrl, noneToken());

            assert.equal(response.status, 401);
        });
    });
});
