// src/modules/movimientos/movimientos.routes.ts
import { Router } from "express";

const router = Router();

router.post("/list", async (_req, res) => {
  return res.json({
    rows: [],
    total: 0,
    page: 1,
    pageSize: 50,
  });
});

export default router;
