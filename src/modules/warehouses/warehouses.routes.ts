import { Router } from "express";
import { requireAuth } from "../../middlewares/requireAuth.js";
import * as controller from "./warehouses.controller.js";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { uploadWarehouseAttachmentMiddleware } from "../../middlewares/uploadWarehouseAttachments.js";

const router = Router();

router.use(requireAuth);

router.get("/", asyncHandler(controller.list));

router.post("/", asyncHandler(controller.create));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.delete("/:id", asyncHandler(controller.remove));

router.patch("/:id/favorite", asyncHandler(controller.setFavorite));
router.get("/:id/article-stock", asyncHandler(controller.articleStock));
router.get("/:id/metal-stock", asyncHandler(controller.metalStock));

router.get("/:id/attachments", asyncHandler(controller.getAttachments));
router.post("/:id/attachments", uploadWarehouseAttachmentMiddleware, asyncHandler(controller.addAttachment));
router.delete("/:id/attachments/:attachmentId", asyncHandler(controller.deleteAttachment));

export default router;