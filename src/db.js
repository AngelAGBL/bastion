import { MongoClient } from "mongodb";
import { hashPassword } from "./auth.js";

const client = new MongoClient(process.env.MONGO_URI);
let db;

export async function connectDB() {
  await client.connect();
  db = client.db();
  await db.collection("users").createIndex({ username: 1 }, { unique: true });
  await db.collection("certificates").createIndex({ fingerprint: 1 }, { unique: true });
  await db.collection("endpoints").createIndex({ targetId: 1 }, { unique: true });
  await db.collection("audit_logs").createIndex({ ts: -1 });
  await db.collection("audit_logs").createIndex({ fingerprint: 1, ts: -1 });

  // Seed default admin
  const exists = await db.collection("users").findOne({ username: "admin" });
  if (!exists) {
    const hashed = await hashPassword("123456");
    await db.collection("users").insertOne({ username: "admin", password: hashed });
    console.log("[db] seeded admin user (admin:123456)");
  }

  console.log("[db] connected");
}

export function getDB() {
  return db;
}
