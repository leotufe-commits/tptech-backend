import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./article-movements.controller.js";

const router = Router();

// Lista (acepta GET con query params o POST con body para filtros complejos)
router.get("/", asyncHandler(controller.list));
router.post("/list", asyncHandler(controller.list));

// Crear movimiento (IN / OUT / ADJUST / OPENING)
router.post("/", asyncHandler(controller.create));

// Transferencia entre almacenes
router.post("/transfer", asyncHandler(controller.transfer));

// Anular movimiento
router.post("/:id/void", asyncHandler(controller.voidMovement));

export default router;
