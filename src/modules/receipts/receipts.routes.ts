// src/modules/receipts/receipts.routes.ts
import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./receipts.controller.js";
import { uploadReceiptAttachmentMiddleware } from "../../middlewares/uploadReceiptAttachments.js";

const router = Router();

router.post("/", asyncHandler(controller.createDraft));

// ===========================================================================
// Attachments
// ===========================================================================
router.get(   "/:id/attachments",                       asyncHandler(controller.listAttachments));
router.post(  "/:id/attachments", ...uploadReceiptAttachmentMiddleware, asyncHandler(controller.addAttachment));
router.patch( "/:id/attachments/:attachmentId",         asyncHandler(controller.updateAttachmentLabel));
router.delete("/:id/attachments/:attachmentId",         asyncHandler(controller.removeAttachment));

export default router;
