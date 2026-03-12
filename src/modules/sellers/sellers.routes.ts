import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { uploadSellerAvatarMiddleware } from "../../middlewares/uploadSellerAvatar.js";
import { uploadSellerAttachmentMiddleware } from "../../middlewares/uploadSellerAttachments.js";
import * as controller from "./sellers.controller.js";

const router = Router();

router.get("/", asyncHandler(controller.list));
router.post("/", asyncHandler(controller.create));
router.put("/:id", asyncHandler(controller.update));
router.patch("/:id/toggle", asyncHandler(controller.toggle));
router.patch("/:id/favorite", asyncHandler(controller.setFavorite));
router.delete("/:id", asyncHandler(controller.remove));

// Avatar
router.patch("/:id/avatar", uploadSellerAvatarMiddleware, asyncHandler(controller.uploadAvatar));

// Attachments
router.post("/:id/attachments", uploadSellerAttachmentMiddleware, asyncHandler(controller.addAttachment));
router.delete("/:id/attachments/:attachmentId", asyncHandler(controller.deleteAttachment));

export default router;
