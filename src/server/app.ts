import { fileURLToPath } from "node:url";
import express, { type Express } from "express";
import jwt from "jsonwebtoken";
import type { LoginBody, TokenUser } from "../utils/types.ts";
import { findUser } from "../utils/users.ts";

const publicDir = fileURLToPath(new URL("../../public", import.meta.url));

export type ReadUser = (token: string) => TokenUser | undefined;

// Uses the requested lifetime, or one hour when it is missing.
function lifetimeSeconds(value: unknown): number {
    if (typeof value === "number" && Number.isInteger(value) && value > 0) {
        return value;
    }

    return 3600;
}

// Builds the login server with the given secret and token check.
export function createApp(secret: string, readUser: ReadUser, mode: string): Express {
    const app = express();

    app.use(express.json());

    // Checks the password and returns a signed token.
    app.post("/login", (req, res) => {
        const body = req.body as LoginBody;
        const user = findUser(body.username, body.password);

        if (!user) {
            res.status(401).json({ error: "invalid login" });
            return;
        }

        const claims: TokenUser = { username: user.username, role: user.role };
        const token = jwt.sign(claims, secret, {
            algorithm: "HS256",
            expiresIn: lifetimeSeconds(body.expiresInSeconds),
        });

        res.json({ token });
    });

    // Returns the user from the bearer token.
    app.get("/me", (req, res) => {
        const header = req.header("authorization");
        const token = header?.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
        const user = token.length > 0 ? readUser(token) : undefined;

        if (!user) {
            res.status(401).json({ error: "unauthorized" });
            return;
        }

        res.json(user);
    });

    // Says which server this process is.
    app.get("/mode", (_req, res) => {
        res.json({ mode });
    });

    // Serves the lab page. Only files in public/ are exposed.
    app.use(express.static(publicDir));

    return app;
}
