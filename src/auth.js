import { SignJWT, jwtVerify } from "jose";
import { getDB } from "./db.js";
import crypto from "node:crypto";

const enc = new TextEncoder();

function getSecret() {
  return enc.encode(process.env.JWT_SECRET);
}

export async function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(plain, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

export async function verifyPassword(plain, stored) {
  const [salt, hash] = stored.split(":");
  const check = crypto.scryptSync(plain, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(check, "hex"));
}

export async function createToken(userId) {
  return new SignJWT({ sub: userId.toString() })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("8h")
    .sign(getSecret());
}

export async function verifyToken(token) {
  const { payload } = await jwtVerify(token, getSecret());
  return payload;
}

/** API auth — returns 401 JSON */
export function authMiddleware(req, res, next) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/token=([^;]+)/);
  if (!match) return res.status(401).json({ error: "unauthorized" });

  verifyToken(match[1])
    .then((payload) => {
      req.userId = payload.sub;
      next();
    })
    .catch(() => res.status(401).json({ error: "unauthorized" }));
}

/** Page auth — redirects to login */
export function pageAuth(req, res, next) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/token=([^;]+)/);
  if (!match) return res.redirect("/auth/login");

  verifyToken(match[1])
    .then(async (payload) => {
      req.userId = payload.sub;
      const db = getDB();
      req.user = await db.collection("users").findOne(
        { _id: new (await import("mongodb")).ObjectId(payload.sub) },
        { projection: { password: 0 } }
      );
      if (!req.user) return res.redirect("/auth/login");
      next();
    })
    .catch(() => res.redirect("/auth/login"));
}
