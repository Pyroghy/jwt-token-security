import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";
import type { LoginBody, LoginResponse } from "../src/utils/types.ts";

// Starts the app on a free localhost port, then stops it.
export async function withServer(app: Express, run: (baseUrl: string) => Promise<void>): Promise<void> {
    const server: Server = app.listen(0, "127.0.0.1");

    await once(server, "listening");

    const address = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
        await run(baseUrl);
    } finally {
        await new Promise<void>((resolve, reject) => {
            server.close((error) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve();
            });
        });
    }
}

// Logs in as user and returns the token.
export async function login(baseUrl: string, expiresInSeconds?: number): Promise<string> {
    const body: LoginBody = {
        username: "user",
        password: "password",
    };

    if (expiresInSeconds !== undefined) {
        body.expiresInSeconds = expiresInSeconds;
    }

    const response = await fetch(`${baseUrl}/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });

    if (response.status !== 200) {
        throw new Error(`login failed with ${response.status}`);
    }

    const json = (await response.json()) as LoginResponse;

    return json.token;
}

// Calls GET /me, with the token when one is given.
export async function me(baseUrl: string, token?: string): Promise<Response> {
    const headers: Record<string, string> = {};

    if (token) {
        headers.authorization = `Bearer ${token}`;
    }

    return fetch(`${baseUrl}/me`, { headers });
}
