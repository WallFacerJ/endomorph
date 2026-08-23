import { chromium } from "@playwright/test";
import { pathToFileURL } from "node:url";
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1500, height: 950 } });
const errs = [];
p.on("pageerror", e => errs.push(e.message));
await p.goto(pathToFileURL(process.argv[2]).href, { waitUntil: "networkidle" });
await p.waitForTimeout(4500);
try { await p.getByRole("button", { name: "Got it" }).click({ timeout: 4000 }); } catch {}
const opts = await p.locator("select").first().locator("option").allInnerTexts();
console.log("scenarios:", opts.length, "->", opts.slice(0,7).join(" / "));
await p.getByRole("navigation").getByRole("button", { name: /^Case/ }).click();
await p.waitForTimeout(1800);
console.log("report panel:", await p.getByRole("region", { name: "Case report" }).count());
console.log("errors:", errs.slice(0,2).join(" | ") || "none");
await b.close();
