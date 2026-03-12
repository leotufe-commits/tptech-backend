import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./attribute-defs.controller.js";

const router = Router();

/* =========================
   CRUD definiciones globales
========================= */
router.get("/", asyncHandler(controller.list));
router.post("/", asyncHandler(controller.create));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.delete("/:id", asyncHandler(controller.remove));

/* =========================
   Opciones de una definición
   Nota: /options/:optionId antes de /:id/options para evitar ambigüedades
========================= */
router.put("/options/:optionId", asyncHandler(controller.updateOption));
router.patch("/options/:optionId/toggle", asyncHandler(controller.toggleOption));
router.delete("/options/:optionId", asyncHandler(controller.removeOption));

router.post("/:id/options", asyncHandler(controller.createOption));
router.patch("/:id/options/reorder", asyncHandler(controller.reorderOptions));

export default router;
