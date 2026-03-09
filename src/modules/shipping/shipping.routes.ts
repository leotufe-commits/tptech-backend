import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./shipping.controller.js";

const router = Router();

router.get("/", asyncHandler(controller.list));
router.post("/", asyncHandler(controller.create));
router.post("/:id/clone", asyncHandler(controller.clone));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.patch("/:id/favorite", asyncHandler(controller.setFavorite));
router.delete("/:id", asyncHandler(controller.remove));

export default router;
