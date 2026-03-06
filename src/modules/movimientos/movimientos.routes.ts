// src/modules/movimientos/movimientos.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";

import {
  list,
  create,
  transfer,
  adjustMovement,
  voidMovement,
  listForWarehouse,
} from "./movimientos.controller.js";

const router = Router();

router.post("/list", requireAuth, list);
router.post("/create", requireAuth, create);
router.post("/transfer", requireAuth, transfer);
router.post("/adjust", requireAuth, adjustMovement);
router.post("/:id/void", requireAuth, voidMovement);

/* ✅ NUEVO
   últimos movimientos de un almacén */
router.get("/warehouse/:id", requireAuth, listForWarehouse);

export default router;