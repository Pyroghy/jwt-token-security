const wordlist = ["password", "123456", "admin", "letmein", "qwerty", "secret", "secret123", "jwt", "changeme"];
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const guessPause = reduceMotion ? 0 : 150;
const attackNames = ["notoken", "none", "secret", "expiry"];
const forgedMarks = { username: "", role: "changed" };

let loginToken = "";
let busy = false;
let currentMode = "";

function el(tag, className, content) {
    const node = document.createElement(tag);

    if (className) {
        node.className = className;
    }

    if (content !== undefined) {
        for (const child of [].concat(content)) {
            if (child !== null && child !== false) {
                node.append(child);
            }
        }
    }

    return node;
}

function code(text) {
    return el("code", "", text);
}

// Builds an icon from one of the Lucide symbols at the top of the page.
function icon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");

    svg.setAttribute("class", "lucide");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);

    return svg;
}

function pause(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function base64url(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function text64(value) {
    return base64url(new TextEncoder().encode(value));
}

function decodePart(part) {
    const padded = part.replaceAll("-", "+").replaceAll("_", "/");
    const json = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "="));

    return JSON.parse(json);
}

async function hmac(secret, data) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));

    return base64url(new Uint8Array(signature));
}

async function signAdmin(secret) {
    const header = text64(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = text64(
        JSON.stringify({
            username: "admin",
            role: "admin",
            exp: Math.floor(Date.now() / 1000) + 3600,
        })
    );
    const data = `${header}.${payload}`;
    const signature = await hmac(secret, data);

    return `${data}.${signature}`;
}

function noneToken() {
    const header = text64(JSON.stringify({ alg: "none", typ: "JWT" }));
    const payload = text64(
        JSON.stringify({
            username: "admin",
            role: "admin",
            exp: Math.floor(Date.now() / 1000) + 3600,
        })
    );

    return `${header}.${payload}.`;
}

async function callMe(token) {
    const headers = {};

    if (token) {
        headers.authorization = `Bearer ${token}`;
    }

    const response = await fetch("/me", { headers });
    const body = await response.json();

    return { status: response.status, body };
}

async function doLogin(expiresInSeconds) {
    const payload = { username: "user", password: "password" };

    if (expiresInSeconds !== undefined) {
        payload.expiresInSeconds = expiresInSeconds;
    }

    const response = await fetch("/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
    });

    if (response.status !== 200) {
        throw new Error(`login failed with ${response.status}`);
    }

    const json = await response.json();

    return json.token;
}

function statusText(status) {
    if (status === 200) {
        return "200 OK";
    }

    if (status === 401) {
        return "401 Unauthorized";
    }

    return String(status);
}

function formatClock(seconds) {
    return new Date(seconds * 1000).toLocaleTimeString([], {
        hour: "numeric",
        minute: "2-digit",
        second: "2-digit",
    });
}

function formatSpan(seconds) {
    if (seconds >= 3600 && seconds % 3600 === 0) {
        return `${seconds / 3600} h`;
    }

    if (seconds >= 60) {
        return `${Math.round(seconds / 60)} min`;
    }

    return `${seconds} s`;
}

function serverDownMessage() {
    const script = currentMode === "fixed" ? "fixed" : "vuln";

    return `Could not reach the server. Start it with npm run start:${script} and try again.`;
}

// Returns readable times for iat and exp.
function timeNotes(payload) {
    const notes = {};

    if (typeof payload.iat === "number") {
        notes.iat = formatClock(payload.iat);
    }

    if (typeof payload.exp === "number") {
        notes.exp = formatClock(payload.exp);

        if (typeof payload.iat === "number") {
            notes.exp += `, iat + ${formatSpan(payload.exp - payload.iat)}`;
        }
    }

    return notes;
}

// Prints an object one key per line and highlights the marked keys.
function jsonBlock(value, marks, notes) {
    const keys = Object.keys(value);
    const lines = [el("div", "json-line", el("span", "jc", "{"))];

    keys.forEach((key, index) => {
        const comma = index < keys.length - 1 ? "," : "";
        const line = el(
            "div",
            "json-line",
            el("span", "jc", ["  ", el("span", "jk", JSON.stringify(key)), ": ", JSON.stringify(value[key]), comma])
        );
        const note = key in marks ? marks[key] : notes[key];

        if (key in marks) {
            line.classList.add("changed");
        }

        if (note) {
            line.append(el("span", "jn", note));
        }

        lines.push(line);
    });

    lines.push(el("div", "json-line", el("span", "jc", "}")));

    return el("div", "json", lines);
}

function block(label, content) {
    return el("div", "out-block", [label ? el("p", "out-label", label) : null].concat(content));
}

function emptyBlock(text) {
    return block("", el("p", "out-empty", text));
}

// Shows a token in its three colors, then each part decoded.
function tokenView(token, options) {
    const parts = token.split(".");
    const line = el("p", "token", [
        el("span", "seg-h", parts[0]),
        el("span", "dot", "."),
        el("span", "seg-p", parts[1]),
        el("span", "dot", "."),
    ]);

    line.append(parts[2] ? el("span", "seg-s", parts[2]) : el("span", "no-sig", "(empty signature)"));

    return [
        line,
        el("div", "decoded", [
            el("div", "decoded-part", [
                el("p", "part-name seg-h", "Header"),
                jsonBlock(decodePart(parts[0]), options.headerMarks || {}, {}),
            ]),
            el("div", "decoded-part", [
                el("p", "part-name seg-p", "Payload"),
                jsonBlock(decodePart(parts[1]), options.payloadMarks || {}, timeNotes(decodePart(parts[1]))),
            ]),
            el("div", "decoded-part sig-part", [
                el("p", "part-name seg-s", "Signature"),
                parts[2] ? el("p", "sig-value", parts[2]) : null,
                el("p", "sig-note", options.signatureNote),
            ]),
        ]),
    ];
}

function responseBlock(result, tone, message) {
    const status = el("span", "status", [icon(tone === "accepted" ? "lock-open" : "lock"), statusText(result.status)]);

    status.dataset.tone = tone;

    return block("Response", [
        el("div", "response-line", [el("span", "", "GET /me"), status]),
        el("p", "verdict-text", message),
        jsonBlock(result.body, {}, {}),
    ]);
}

function show(name, blocks) {
    const node = document.getElementById(`${name}-output`);

    node.replaceChildren(...blocks);
}

const resultIcons = {
    running: "loader-circle",
    ok: "circle-check",
    accepted: "lock-open",
    rejected: "lock",
    error: "circle-alert",
};

function setResult(name, tone, text) {
    const cell = document.querySelector(`[data-result="${name}"]`);

    cell.dataset.tone = tone;
    cell.replaceChildren(resultIcons[tone] ? icon(resultIcons[tone]) : "", text);
}

// Shows the GET /me result in the table and returns its tone.
function finish(name, result) {
    if (result.status === 200) {
        setResult(name, "accepted", "200, got in");
        return "accepted";
    }

    setResult(name, "rejected", `${result.status}, rejected`);
    return "rejected";
}

// Shows the login token with its parts decoded.
function showLogin(token) {
    const payload = decodePart(token.split(".")[1]);

    loginToken = token;
    feedField("POST /login 200", token);
    show("login", [
        block(
            "Token",
            tokenView(token, {
                signatureNote: "HMAC-SHA256 of header.payload with the server's secret",
            })
        ),
        block("Response", [
            el("div", "response-line", [
                el("span", "", "POST /login"),
                el("span", "status", [icon("circle-check"), "200 OK"]),
            ]),
            el("p", "verdict-text", `Logged in as ${payload.username} with role ${payload.role}.`),
        ]),
    ]);
    setResult("login", "ok", "200 OK");
}

async function runLogin() {
    const button = document.getElementById("login-button");

    button.classList.add("is-running");
    setResult("login", "running", "running");

    try {
        showLogin(await doLogin());
    } catch {
        setResult("login", "error", "no answer");
        show("login", [emptyBlock(serverDownMessage())]);
    } finally {
        button.classList.remove("is-running");
    }
}

// Calls GET /me with no token.
async function attackNoToken() {
    show("notoken", [emptyBlock("Waiting for the server...")]);

    const result = await callMe("");
    const tone = finish("notoken", result);

    feedField(`GET /me ${result.status}`);
    show("notoken", [
        responseBlock(
            result,
            tone,
            tone === "accepted" ? "Accepted with no token at all." : "Rejected. There is no token to check."
        ),
    ]);
}

// Shows the alg none token with the changed fields marked.
function noneTokenBlock(label, token) {
    return block(
        label,
        tokenView(token, {
            headerMarks: { alg: "no check" },
            payloadMarks: forgedMarks,
            signatureNote: "Nothing to verify when alg is none",
        })
    );
}

// Sends an unsigned admin token with alg none.
async function attackNone() {
    const token = noneToken();

    show("none", [noneTokenBlock("Token sent", token), emptyBlock("Waiting for the server...")]);

    const result = await callMe(token);
    const tone = finish("none", result);

    feedField(token, `GET /me ${result.status}`);
    show("none", [
        noneTokenBlock("Token sent", token),
        responseBlock(
            result,
            tone,
            tone === "accepted"
                ? `Accepted. Logged in as ${result.body.username} with no signature at all.`
                : "Rejected. alg none is not allowed."
        ),
    ]);
}

// Guesses the secret from the login token, then signs an admin token.
async function attackSecret() {
    const guessList = el("ul", "log guesses");
    let found = "";

    show("secret", [emptyBlock("Starting...")]);

    if (!loginToken) {
        showLogin(await doLogin());
    }

    const parts = loginToken.split(".");
    const data = `${parts[0]}.${parts[1]}`;
    const guessBlock = block("Guessing the secret", [
        el("p", "target", ["Login token signature: ", code(parts[2])]),
        guessList,
    ]);

    show("secret", [guessBlock]);

    for (const word of wordlist) {
        const guess = await hmac(word, data);
        const matched = guess === parts[2];
        const verdict = el("span", "guess-verdict", matched ? [icon("key-round"), "match"] : "no match");
        const row = el("li", matched ? "hit" : "", [el("span", "", word), el("span", "guess-sig", guess), verdict]);

        guessList.append(row);
        feedField(`HMAC("${word}") ${guess}`);
        await pause(guessPause);

        if (matched) {
            found = word;
            break;
        }
    }

    guessBlock.append(
        found
            ? el("p", "found", ["Secret found: ", code(found)])
            : el("p", "found", ["No match in the list. Trying ", code("secret123"), " anyway."])
    );

    const token = await signAdmin(found || "secret123");
    const forgedBlock = block(
        "Token sent",
        tokenView(token, {
            payloadMarks: forgedMarks,
            signatureNote: found
                ? "Signed with the guessed secret"
                : "Signed with secret123, which this server doesn't use",
        })
    );

    show("secret", [guessBlock, forgedBlock, emptyBlock("Waiting for the server...")]);

    const result = await callMe(token);
    const tone = finish("secret", result);

    feedField(token, `GET /me ${result.status}`);
    show("secret", [
        guessBlock,
        forgedBlock,
        responseBlock(
            result,
            tone,
            tone === "accepted"
                ? "Accepted. The server can't tell this token from one it made."
                : "Rejected. The signature doesn't match the server's secret."
        ),
    ]);
}

// Builds one line of the expiry log.
function logLine(start, message, sub) {
    const time = `${((Date.now() - start) / 1000).toFixed(2)} s`;
    const text = el("span", "msg", [message, sub ? el("span", "sub", sub) : null]);

    return el("li", "", [el("span", "t", time), text, el("span", "")]);
}

function setLineResult(line, result, tone) {
    const slot = line.lastElementChild;

    slot.textContent = statusText(result.status);
    slot.dataset.tone = tone;
}

// Uses a token after its exp time has passed.
async function attackExpiry() {
    const start = Date.now();
    const log = el("ul", "log");
    const logBlock = block("Log", log);

    show("expiry", [logBlock]);

    const token = await doLogin(1);
    const payload = decodePart(token.split(".")[1]);
    const expMs = payload.exp * 1000;

    log.append(
        logLine(start, "POST /login with expiresInSeconds: 1", `exp = ${payload.exp} (${formatClock(payload.exp)})`)
    );

    const before = await callMe(token);
    const beforeLine = logLine(start, "GET /me with the fresh token");

    setLineResult(beforeLine, before, before.status === 200 ? "" : "rejected");
    log.append(beforeLine);

    const waitLine = logLine(start, "Waiting for exp to pass");
    const waitText = el("span", "sub", "");

    waitLine.querySelector(".msg").append(waitText);
    log.append(waitLine);

    const ticker = setInterval(() => {
        const now = Date.now();

        waitText.textContent =
            now < expMs
                ? `${((expMs - now) / 1000).toFixed(1)} s left`
                : `expired ${((now - expMs) / 1000).toFixed(1)} s ago`;
    }, 100);

    await pause(Math.max(expMs - Date.now() + 1100, 0));
    clearInterval(ticker);
    waitText.textContent = `expired ${((Date.now() - expMs) / 1000).toFixed(1)} s ago`;

    const after = await callMe(token);
    const afterLine = logLine(start, "GET /me with the same token");
    const tone = finish("expiry", after);
    const lateBy = ((Date.now() - expMs) / 1000).toFixed(1);

    setLineResult(afterLine, after, tone);
    log.append(afterLine);
    feedField(token, `exp=${payload.exp}`, `GET /me ${after.status}`);
    show("expiry", [
        logBlock,
        responseBlock(
            after,
            tone,
            tone === "accepted"
                ? `Accepted. The token expired ${lateBy} s ago and still works.`
                : "Rejected. The token is past exp."
        ),
    ]);
}

const attacks = { notoken: attackNoToken, none: attackNone, secret: attackSecret, expiry: attackExpiry };

async function runAttack(name) {
    const button = document.querySelector(`[data-attack="${name}"]`);

    button.classList.add("is-running");
    setResult(name, "running", "running");

    try {
        await attacks[name]();
    } catch {
        setResult(name, "error", "no answer");
        show(name, [emptyBlock(serverDownMessage())]);
    } finally {
        button.classList.remove("is-running");
    }
}

// Runs one task at a time so tests never overlap.
async function withLock(task) {
    if (busy) {
        return;
    }

    busy = true;

    for (const button of document.querySelectorAll("[data-action]")) {
        button.disabled = true;
    }

    try {
        await task();
    } finally {
        busy = false;

        for (const button of document.querySelectorAll("[data-action]")) {
            button.disabled = false;
        }
    }
}

// Clears every result and puts the page back to how it loads.
function resetPage() {
    loginToken = "";

    for (const name of ["login", ...attackNames]) {
        setResult(name, "idle", "not run");
    }

    show("login", [emptyBlock("No token yet.")]);
    show("notoken", [emptyBlock("Not sent yet.")]);
    show("none", [noneTokenBlock("Token to send", noneToken()), emptyBlock("Not sent yet.")]);
    show("secret", [
        block(
            "Wordlist",
            el(
                "ul",
                "words",
                wordlist.map((word) => el("li", "", word))
            )
        ),
        emptyBlock("Not run yet."),
    ]);
    show("expiry", [emptyBlock("Not run yet.")]);
}

function applyMode(mode) {
    currentMode = mode;
    document.body.dataset.mode = mode;

    if (mode === "vulnerable" || mode === "fixed") {
        document.getElementById("mode-name").textContent = mode;
        return;
    }

    document.getElementById("mode-name").textContent = "not reachable";
    document
        .getElementById("mode-note")
        .replaceChildren("Start a server with ", code("npm run start:vuln"), " and reload this page.");
}

async function loadMode() {
    try {
        const response = await fetch("/mode");
        const json = await response.json();

        applyMode(json.mode);
    } catch {
        applyMode("offline");
    }
}

document.getElementById("login-button").addEventListener("click", () => withLock(runLogin));

for (const button of document.querySelectorAll("[data-attack]")) {
    button.addEventListener("click", () => withLock(() => runAttack(button.dataset.attack)));
}

document.getElementById("run-all").addEventListener("click", () => {
    const button = document.getElementById("run-all");

    withLock(async () => {
        button.classList.add("is-running");

        try {
            if (!loginToken) {
                await runLogin();
            }

            for (const name of attackNames) {
                await runAttack(name);
            }
        } finally {
            button.classList.remove("is-running");
        }
    });
});

// Background text made from the lab's own traffic. It lights up around the pointer.
const field = document.getElementById("field");
const fieldCtx = field.getContext("2d");
const fieldFont = '12px "IBM Plex Mono", "Cascadia Mono", Consolas, monospace';
const fieldLine = 18;
const fieldRadius = 170;
const fieldBaseAlpha = 0.035;
const fieldAlpha = 0.2;
const hexChars = "0123456789abcdef";
const b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const headerHS256 = text64(JSON.stringify({ alg: "HS256", typ: "JWT" }));
const headerNone = text64(JSON.stringify({ alg: "none", typ: "JWT" }));
const trafficLines = [
    "GET /me 200",
    "GET /me 401",
    "POST /login 200",
    '{"error":"unauthorized"}',
    '{"username":"admin","role":"admin"}',
    `Authorization: Bearer ${headerHS256}`,
    "alg=HS256",
    "alg=none",
    "HMAC-SHA256",
    "ignoreExpiration: true",
];
const pointer = { x: 0, y: 0, tx: 0, ty: 0, strength: 0, target: 0, seen: false };
const fieldColor = getComputedStyle(document.documentElement).getPropertyValue("--muted").trim();
let fieldRows = [];
let fieldCell = 7.2;
let fieldRunning = false;

function pick(source, length) {
    let out = "";

    for (let i = 0; i < length; i++) {
        out += source[Math.floor(Math.random() * source.length)];
    }

    return out;
}

function oneOf(list) {
    return list[Math.floor(Math.random() * list.length)];
}

// Builds a payload like the ones this server signs.
function samplePayload() {
    const iat = Math.floor(Date.now() / 1000) - Math.floor(Math.random() * 86400);
    const name = Math.random() < 0.7 ? "user" : "admin";

    return text64(JSON.stringify({ username: name, role: name, iat, exp: iat + 3600 }));
}

function fieldChunk() {
    const roll = Math.random();

    if (roll < 0.32) {
        return `${Math.random() < 0.8 ? headerHS256 : headerNone}.${samplePayload()}.${pick(b64Chars, 43)}`;
    }

    if (roll < 0.5) {
        return pick(hexChars, 64);
    }

    if (roll < 0.64) {
        return `HMAC("${oneOf(wordlist)}") ${pick(b64Chars, 43)}`;
    }

    if (roll < 0.76) {
        return `exp=${Math.floor(Date.now() / 1000) + Math.floor(Math.random() * 7200) - 3600}`;
    }

    return oneOf(trafficLines);
}

function layoutField() {
    const scale = window.devicePixelRatio || 1;
    const width = window.innerWidth;
    const height = window.innerHeight;

    field.width = Math.floor(width * scale);
    field.height = Math.floor(height * scale);
    field.style.width = `${width}px`;
    field.style.height = `${height}px`;
    fieldCtx.setTransform(scale, 0, 0, scale, 0, 0);
    fieldCtx.font = fieldFont;
    fieldCtx.textBaseline = "middle";
    fieldCtx.fillStyle = fieldColor;
    fieldCell = fieldCtx.measureText("0").width || 7.2;

    const cols = Math.ceil(width / fieldCell) + 1;
    const rows = Math.ceil(height / fieldLine) + 1;

    fieldRows = [];

    for (let r = 0; r < rows; r++) {
        let text = pick(hexChars, Math.floor(Math.random() * 12));

        while (text.length < cols) {
            text += `${fieldChunk()} `;
        }

        fieldRows.push(text.split(""));
    }

    paintField();
}

function drawField() {
    const ease = reduceMotion ? 1 : 0.12;

    pointer.x += (pointer.tx - pointer.x) * ease;
    pointer.y += (pointer.ty - pointer.y) * ease;
    pointer.strength += (pointer.target - pointer.strength) * (reduceMotion ? 1 : 0.06);
    fieldCtx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    fieldCtx.globalAlpha = fieldBaseAlpha;

    fieldRows.forEach((row, r) => {
        fieldCtx.fillText(row.join(""), 0, r * fieldLine + fieldLine / 2);
    });

    fieldCtx.globalAlpha = 1;

    if (pointer.strength < 0.01) {
        return;
    }

    const firstRow = Math.max(0, Math.floor((pointer.y - fieldRadius) / fieldLine));
    const lastRow = Math.min(fieldRows.length - 1, Math.ceil((pointer.y + fieldRadius) / fieldLine));

    for (let r = firstRow; r <= lastRow; r++) {
        const row = fieldRows[r];
        const y = r * fieldLine + fieldLine / 2;
        const dy = y - pointer.y;
        const reach = Math.sqrt(Math.max(fieldRadius * fieldRadius - dy * dy, 0));
        const firstCol = Math.max(0, Math.floor((pointer.x - reach) / fieldCell));
        const lastCol = Math.min(row.length - 1, Math.ceil((pointer.x + reach) / fieldCell));

        for (let c = firstCol; c <= lastCol; c++) {
            const x = c * fieldCell;
            const falloff = 1 - Math.hypot(x - pointer.x, dy) / fieldRadius;

            if (falloff <= 0 || row[c] === " ") {
                continue;
            }

            // Sometimes flips a hex character near the pointer.
            if (!reduceMotion && falloff > 0.5 && Math.random() < 0.003 && hexChars.includes(row[c])) {
                row[c] = pick(hexChars, 1);
            }

            fieldCtx.globalAlpha = falloff * falloff * fieldAlpha * pointer.strength;
            fieldCtx.fillText(row[c], x, y);
        }
    }

    fieldCtx.globalAlpha = 1;
}

function fieldFrame() {
    drawField();

    if (pointer.target > 0 || pointer.strength > 0.01) {
        requestAnimationFrame(fieldFrame);
        return;
    }

    fieldRunning = false;
}

function wakeField() {
    if (!fieldRunning) {
        fieldRunning = true;
        requestAnimationFrame(fieldFrame);
    }
}

// Redraws the background when nothing is animating.
function paintField() {
    if (!fieldRunning) {
        drawField();
    }
}

// Writes text from a test into a random spot in the background.
function feedField(...texts) {
    for (const text of texts) {
        const row = fieldRows[Math.floor(Math.random() * fieldRows.length)];

        if (!row) {
            return;
        }

        const start = Math.floor(Math.random() * Math.max(row.length - text.length, 1));

        for (let i = 0; i < text.length && start + i < row.length; i++) {
            row[start + i] = text[i];
        }
    }

    paintField();
}

window.addEventListener("pointermove", (event) => {
    pointer.tx = event.clientX;
    pointer.ty = event.clientY;

    if (!pointer.seen) {
        pointer.x = pointer.tx;
        pointer.y = pointer.ty;
        pointer.seen = true;
    }

    pointer.target = 1;
    wakeField();
});

document.documentElement.addEventListener("pointerleave", () => {
    pointer.target = 0;
    pointer.seen = false;
});

window.addEventListener("resize", () => {
    layoutField();
    wakeField();
});

document.fonts.ready.then(layoutField);
layoutField();

document.getElementById("reset").addEventListener("click", () => withLock(async () => resetPage()));
document.getElementById("address").textContent = location.host || "127.0.0.1:3000";
resetPage();
loadMode();
