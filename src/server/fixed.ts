import { randomBytes } from "node:crypto";
import jwt from "jsonwebtoken";
import type { JwtPayload, TokenUser } from "../utils/types.ts";
import { createApp } from "./app.ts";

// 32 random bytes (256 bits), new each time the server starts. Nothing to guess and nothing in the source.
const FIXED_SECRET = randomBytes(32).toString("hex");

// Reads the user from an HS256 token and rejects anything else.
function readUser(token: string): TokenUser | undefined {
    try {
        const decoded = jwt.verify(token, FIXED_SECRET, { algorithms: ["HS256"] }) as string | JwtPayload;

        if (typeof decoded === "string" || typeof decoded.username !== "string" || typeof decoded.role !== "string") {
            return undefined;
        }

        return { username: decoded.username, role: decoded.role };
    } catch {
        return undefined;
    }
}

export const app = createApp(FIXED_SECRET, readUser, "fixed");
