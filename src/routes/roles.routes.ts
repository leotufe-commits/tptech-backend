// src/routes/roles.routes.ts
import { Router } from "express";

const router = Router();

// Placeholder: más adelante metemos CRUD real
router.get("/", (_req, res) => {
  res.json({ ok: true, module: "roles", message: "Not implemented yet" });
});

export default router;
