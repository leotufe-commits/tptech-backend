// tptech-backend/src/modules/users/users.routes.ts
import { Router } from "express";

import { requireAuth } from "../../middlewares/requireAuth.js";
import { requirePermission } from "../../middlewares/requirePermission.js";

import { uploadAvatarMiddleware } from "../../middlewares/uploadAvatar.js";

import * as Core from "./users.core.js";
import * as Pin from "./users.quickpin.js";
import * as Attachments from "./users.attachments.js";

import { uploadMyAvatar, deleteMyAvatar, uploadUserAvatar, deleteUserAvatar } from "./users.avatar.js";

import { uploadUserAttachmentsFiles, handleMulterErrors } from "../../middlewares/uploadUserAttachments.js";

const router = Router();

/* =========================
   AUTH
========================= */
router.use(requireAuth);

/* =========================
   Gates
========================= */
const requireUsersView = requirePermission("USERS_ROLES", "VIEW");
const requireUsersAdmin = requirePermission("USERS_ROLES", "ADMIN");

/* =========================================================
   /ME
========================================================= */
router.patch("/me/favorite-warehouse", Core.updateMyFavoriteWarehouse);

router.put("/me/quick-pin", Pin.updateMyQuickPin);
router.delete("/me/quick-pin", Pin.removeMyQuickPin);

// Avatar propio
router.put("/me/avatar", uploadAvatarMiddleware, uploadMyAvatar);
router.delete("/me/avatar", deleteMyAvatar);

// Attachments propios
router.put("/me/attachments", uploadUserAttachmentsFiles, Attachments.uploadMyAttachments);

/* =========================================================
   VIEW
========================================================= */
router.get("/", requireUsersView, Core.listUsers);
router.get("/:id", requireUsersView, Core.getUser);
router.get("/:id/attachments/:attachmentId/download", requireUsersView, Attachments.downloadUserAttachment);

/* =========================================================
   ADMIN
========================================================= */
router.patch("/:id/favorite-warehouse", requireUsersAdmin, Core.updateUserFavoriteWarehouse);

router.put("/:id/quick-pin", requireUsersAdmin, Pin.updateUserQuickPin);
router.delete("/:id/quick-pin", requireUsersAdmin, Pin.removeUserQuickPin);
router.patch("/:id/quick-pin/enabled", requireUsersAdmin, Pin.updateUserQuickPinEnabled);

// Avatar ADMIN
router.put("/:id/avatar", requireUsersAdmin, uploadAvatarMiddleware, uploadUserAvatar);
router.delete("/:id/avatar", requireUsersAdmin, deleteUserAvatar);

// Attachments ADMIN
router.put("/:id/attachments", requireUsersAdmin, uploadUserAttachmentsFiles, Attachments.uploadUserAttachments);
router.delete("/:id/attachments/:attachmentId", requireUsersAdmin, Attachments.deleteUserAttachment);

// Invite
router.post("/:id/invite", requireUsersAdmin, Core.sendUserInvite);

// CRUD user
router.post("/", requireUsersAdmin, Core.createUser);
router.patch("/:id", requireUsersAdmin, Core.updateUserProfile);
router.patch("/:id/status", requireUsersAdmin, Core.updateUserStatus);
router.put("/:id/roles", requireUsersAdmin, Core.assignRolesToUser);

// Overrides
router.post("/:id/overrides", requireUsersAdmin, Core.setUserOverride);
router.delete("/:id/overrides/:permissionId", requireUsersAdmin, Core.removeUserOverride);

// Soft delete
router.delete("/:id", requireUsersAdmin, Core.softDeleteUser);

/* =========================
   Multer error handler
========================= */
router.use((err: any, req: any, res: any, next: any) => {
  if (!err) return next();
  return handleMulterErrors(err, req, res, next);
});

export default router;