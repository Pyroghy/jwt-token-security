# JWT Token Security Lab

CSC 470 Option C2. A small login server with three JWT flaws, one test per flaw, and a fixed server where those same checks fail. Everything listens on localhost.

## Setup

Needs Node.js 18 or newer. Built and tested on Node 22.

```
npm install
```

## Scripts

- `npm run start:vulnerable` starts the broken server at `http://127.0.0.1:3000`
- `npm run start:fixed` starts the fixed server at `http://127.0.0.1:3000`

Both scripts run `src/index.ts`. Only one server runs at a time, so they share the port.

- `npm run test:baseline` checks that a real login token gets 200 and no token gets 401
- `npm run test:none` tries an unsigned admin token
- `npm run test:secret` guesses the HMAC secret, then signs an admin token
- `npm run test:expiry` uses a token after `exp`
- `npm test` runs all four
- `npm run lint` runs Biome

## Walkthrough

1. Run `npm install`.
2. Run `npm run start:vulnerable`, then open `http://127.0.0.1:3000`. This is the lab page, `src/index.html`.
3. Click **Log in as user**. The page shows the real token split into its header, payload and signature.
4. Click each attack button, or **Run all tests**. On the vulnerable server all three forged tokens get 200.
5. Stop the server with Ctrl+C and run `npm run start:fixed`. Reload the page and run the tests again. All three forged tokens get 401, and the real login still gets 200.
6. **Reset** clears the page between runs.
7. `npm test` runs the same three attacks from the command line against both servers. It starts its own servers, so nothing needs to be running.

The page has no outside dependencies and works without internet. It embeds the IBM Plex fonts (SIL Open Font License) and Lucide icons (ISC license).

## Layout

```
src/
  index.ts          starts the vulnerable or fixed server
  index.html        the lab page
  server/
    app.ts          routes shared by both servers
    vulnerable.ts   token check with the three flaws
    fixed.ts        token check with the fixes
  utils/            lab users and shared types
tests/
  baseline.test.ts  real login and no token
  *.test.ts         one exploit per flaw, run against both servers
  helpers.ts        starts a server on a free port for each test
```

## Routes

`POST /login` with `{ "username", "password" }` returns `{ "token" }`. Optional `expiresInSeconds` sets a short lifetime so the expiry test does not wait an hour.

`GET /me` with `Authorization: Bearer <token>` returns `{ "username", "role" }`. A missing or rejected token gets 401 with `{ "error": "unauthorized" }`.

`GET /mode` returns which server is running. The lab page uses it.

Lab users: `user` / `password` (role `user`) and `admin` / `password` (role `admin`).

## The three flaws

1. **alg none.** The vulnerable server reads `alg` from the token and skips the signature when it is `none`. The fixed server allows only HS256.
2. **Weak secret.** The vulnerable secret is the string `secret123`. The test tries a short wordlist written for this lab, then signs a new admin token. The fixed server makes a random 256-bit secret each time it starts, so there is nothing to guess and no secret in the source.
3. **No expiry.** The vulnerable server verifies HS256 with expiry ignored. The fixed server lets `jsonwebtoken` reject expired tokens. A fresh login still works.

## AI disclosure

Claude was used for early planning and Cursor for part of the implementation. Claude Code was used to build the browser demo page (`src/index.html`). The architecture and design decisions were mine.
