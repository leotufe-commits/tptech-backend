import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./sales.controller.js";

const router = Router();

router.post("/preview", asyncHandler(controller.previewSale));
router.get("/", asyncHandler(controller.list));
router.post("/", asyncHandler(controller.create));
router.get("/caja", asyncHandler(controller.cajaSummary));
router.get("/:id", asyncHandler(controller.getOne));
router.put("/:id", asyncHandler(controller.update));
router.post("/:id/confirm", asyncHandler(controller.confirm));
router.post("/:id/payments", asyncHandler(controller.addPayment));
router.patch("/:id/cancel", asyncHandler(controller.cancel));

export default router;
