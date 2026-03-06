// src/modules/movimientos/movimientos.routes.ts
import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import {
  list,
  create,
  transfer,
  adjustMovement,
  voidMovement,
} from "./movimientos.controller.ts";

const router = Router();

router.post("/list", requireAuth, list);
router.post("/create", requireAuth, create);
router.post("/transfer", requireAuth, transfer);
router.post("/adjust", requireAuth, adjustMovement);
router.post("/:id/void", requireAuth, voidMovement);

export default router;