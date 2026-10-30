import jwt from "jsonwebtoken";
import type { JwtHeader, JwtPayload, TokenUser } from "../utils/types.ts";
import { createApp } from "./app.ts";

const VULNERABLE_SECRET = "secret123";

// Returns a user when both claims are strings.
function userFromClaims(username: unknown, role: unknown): TokenUser | undefined {
    if (typeof username !== "string" || typeof role !== "string") {
        return undefined;
    }

    return { username, role };
}

// Reads the user from a token. alg none skips the signature check.
function readUser(token: string): TokenUser | undefined {
    const parts = token.split(".");
    let header: JwtHeader;

    if (parts.length !== 3) {
        return undefined;
    }

    try {
        header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as JwtHeader;
    } catch {
        return undefined;
    }

    // The header is attacker-controlled. alg none skips the signature check.
    if (header.alg === "none") {
        try {
            const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as JwtPayload;

            return userFromClaims(payload.username, payload.role);
        } catch {
            return undefined;
        }
    }

    try {
        const decoded = jwt.verify(token, VULNERABLE_SECRET, { ignoreExpiration: true }) as string | JwtPayload;

        if (typeof decoded === "string") {
            return undefined;
        }

        return userFromClaims(decoded.username, decoded.role);
    } catch {
        return undefined;
    }
}

export const app = createApp(VULNERABLE_SECRET, readUser, "vulnerable");
