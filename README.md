# JWT Token Security Lab

A login server for CSC 470 (Option C2) with three common JWT mistakes built in. Each one has an exploit, and there's a fixed version of the server where the same exploits stop working. Everything runs locally on 127.0.0.1.

## The three flaws

### alg none

A JWT's header says which algorithm was used to sign it. The vulnerable server believes it, so a token with `"alg": "none"` and an empty signature gets accepted without any check. The fixed server only accepts HS256.

### Weak secret

The vulnerable server signs its tokens with `secret123`. Anyone holding one real token can try guesses offline until the HMAC matches, then sign their own admin token. The wordlist is nine words written for this lab, not a leaked password list. The fixed server generates a random 256-bit secret every time it starts, so there's nothing to guess and no secret in the code.

### No expiry

The vulnerable server checks the signature but ignores `exp`, so a stolen token keeps working forever. The fixed server lets `jsonwebtoken` reject expired tokens.

## Running it

You'll need Node.js 18 or newer. It was built and tested on Node 22.

```
npm install
npm run start:vuln
```

Then open http://127.0.0.1:3000. The server serves the lab page itself, so there's nothing else to start. Opening `public/index.html` straight from the folder won't work, because the page needs the server to answer its requests.

1. **Log in as user** gets a real token and shows its header, payload and signature.
2. Each flaw has its own button, or **Run all tests** goes through everything. On the vulnerable server all three forged tokens get a 200.
3. Stop the server with Ctrl+C, start the fixed one with `npm run start:fixed`, reload the page and run them again. This time all three get a 401, and the normal login still works.
4. **Reset** clears the page if you want to run things again.

Both servers use port 3000, so run one at a time. The page doesn't load anything from the internet, so it works offline. The IBM Plex fonts (SIL Open Font License) and Lucide icons (ISC license) ship with it in `public/`.

## Tests

The same attacks run from the command line too. Each test starts its own server on a free port, so nothing needs to be running first.

```
npm test
```

Every attack test runs against both servers. It should get in on the vulnerable one and get a 401 on the fixed one. To run one file on its own, use `npx tsx tests/alg-none.test.ts`.

`npm run lint` checks the code with Biome.

## Routes

- `POST /login` takes `{ "username", "password" }` and returns `{ "token" }`. It also takes an optional `expiresInSeconds`, which is how the expiry test gets a short-lived token instead of waiting an hour.
- `GET /me` reads the `Authorization: Bearer <token>` header and returns `{ "username", "role" }`. A missing or rejected token gets a 401.
- `GET /mode` says which server is running. The lab page uses it.

The lab accounts are `user` / `password` with role `user`, and `admin` / `password` with role `admin`. Both are made up for the lab.

## Project structure

```
public/
  index.html        the lab page
  styles.css
  app.js            runs the attacks from the browser
  fonts/            IBM Plex, kept local so the page works offline
src/
  index.ts          starts the vulnerable or fixed server
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

## AI disclosure

Claude helped with early planning. Cursor helped with part of the implementation. Claude built the browser demo page. The architecture and design decisions were mine.
