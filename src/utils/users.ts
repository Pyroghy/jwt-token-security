import type { User } from "./types.ts";

const users: User[] = [
    { username: "user", password: "password", role: "user" },
    { username: "admin", password: "password", role: "admin" },
];

// Finds the account with this username and password.
export function findUser(username: string | undefined, password: string | undefined): User | undefined {
    if (!username || !password) {
        return undefined;
    }

    return users.find((user) => user.username === username && user.password === password);
}
