import { getDB } from "../services/db.js";
import { verifyPassword } from "../utils/crypto.js";
import { createToken } from "../services/auth.js";
import { render } from "../utils/render.js";

export function registerAuthRoutes(app) {
  app.get("/auth/login", (req, res) => render(res, "auth/login", {}));

  app.post("/auth/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return render(res, "auth/login", { error: "Completa todos los campos" });
      const db = getDB();
      const user = await db.collection("users").findOne({ username });
      if (!user || !(await verifyPassword(password, user.password))) return render(res, "auth/login", { error: "Credenciales inválidas" });
      const token = await createToken(user._id);
      res.setHeader("Set-Cookie", `token=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=28800`);
      res.redirect("/dashboard/clients");
    } catch { render(res, "auth/login", { error: "Error del servidor" }); }
  });

  app.post("/auth/logout", (_req, res) => {
    res.setHeader("Set-Cookie", "token=; HttpOnly; Path=/; Max-Age=0");
    res.redirect("/auth/login");
  });
}
