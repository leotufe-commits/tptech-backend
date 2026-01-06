// src/modules/movimientos/movimientos.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";

const router = Router();

// ✅ secure-by-default: todo el módulo requiere auth
router.use(requireAuth);

router.post("/list", async (_req, res) => {
  return res.json({
    rows: [],
    total: 0,
    page: 1,
    pageSize: 50,
  });
});

export default router;
