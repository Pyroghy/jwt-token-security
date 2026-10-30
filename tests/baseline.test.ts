import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { app as fixedApp } from "../src/server/fixed.ts";
import { app as vulnerableApp } from "../src/server/vulnerable.ts";
import type { TokenUser } from "../src/utils/types.ts";
import { login, me, withServer } from "./helpers.ts";

describe("baseline", () => {
    it("vulnerable server accepts a token from a real login", async () => {
        await withServer(vulnerableApp, async (baseUrl) => {
            const response = await me(baseUrl, await login(baseUrl));

            assert.equal(response.status, 200);

            const body = (await response.json()) as TokenUser;

            assert.equal(body.role, "user");
        });
    });

    it("vulnerable server rejects a request with no token", async () => {
        await withServer(vulnerableApp, async (baseUrl) => {
            const response = await me(baseUrl);

            assert.equal(response.status, 401);
        });
    });

    it("fixed server accepts a token from a real login", async () => {
        await withServer(fixedApp, async (baseUrl) => {
            const response = await me(baseUrl, await login(baseUrl));

            assert.equal(response.status, 200);

            const body = (await response.json()) as TokenUser;

            assert.equal(body.role, "user");
        });
    });

    it("fixed server rejects a request with no token", async () => {
        await withServer(fixedApp, async (baseUrl) => {
            const response = await me(baseUrl);

            assert.equal(response.status, 401);
        });
    });
});
