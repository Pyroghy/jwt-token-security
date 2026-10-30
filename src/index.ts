import type { Express } from "express";
import { app as fixedApp } from "./server/fixed.ts";
import { app as vulnerableApp } from "./server/vulnerable.ts";

const mode = process.argv[2];
const port = 3000;

switch (mode) {
    case "vulnerable":
        start(vulnerableApp, port);
        break;
    case "fixed":
        start(fixedApp, port);
        break;
    default:
        console.error("usage: tsx src/index.ts vulnerable|fixed");
        process.exit(1);
}

// Listens on localhost and prints the address.
function start(app: Express, port: number): void {
    app.listen(port, "127.0.0.1", () => {
        console.log(`${mode} server on http://127.0.0.1:${port}`);
    });
}
