// src/routes/roles.routes.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

const router = Router();

// ✅ secure-by-default: todo el módulo requiere auth
router.use(requireAuth);

// Placeholder: más adelante metemos CRUD real
router.get("/", (_req, res) => {
  res.json({ ok: true, module: "roles", message: "Not implemented yet" });
});

export default router;
