export type TokenUser = {
    username: string;
    role: string;
};

export type User = TokenUser & {
    password: string;
};

export type LoginBody = {
    username?: string;
    password?: string;
    expiresInSeconds?: number;
};

export type LoginResponse = {
    token: string;
};

export type JwtHeader = {
    alg?: string;
    typ?: string;
};

export type JwtPayload = {
    username?: string;
    role?: string;
    exp?: number;
};
