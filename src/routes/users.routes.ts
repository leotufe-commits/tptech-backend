// src/routes/users.routes.ts
import { Router } from "express";

const router = Router();

// Placeholder: más adelante metemos CRUD real
router.get("/", (_req, res) => {
  res.json({ ok: true, module: "users", message: "Not implemented yet" });
});

export default router;
