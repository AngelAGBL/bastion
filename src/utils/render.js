import ejsModule from "ejs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VIEWS = path.join(__dirname, "..", "..", "views");

const ejs = ejsModule.default || ejsModule;

const layoutSrc = fs.readFileSync(path.join(VIEWS, "layout.ejs"), "utf-8");
const layoutFn = ejs.compile(layoutSrc, { filename: path.join(VIEWS, "layout.ejs") });

const cache = {};

function compileView(name) {
  if (cache[name]) return cache[name];
  const file = path.join(VIEWS, name + ".ejs");
  const src = fs.readFileSync(file, "utf-8");
  cache[name] = ejs.compile(src, { filename: file });
  return cache[name];
}

export function render(res, view, data = {}) {
  const bodyHtml = compileView(view)(data);
  const html = layoutFn({ ...data, body: bodyHtml });
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
}
