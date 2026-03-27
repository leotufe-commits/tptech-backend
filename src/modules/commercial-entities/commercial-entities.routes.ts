import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./commercial-entities.controller.js";
import { uploadEntityAvatarMiddleware } from "../../middlewares/uploadEntityAvatar.js";
import { uploadEntityAttachmentMiddleware } from "../../middlewares/uploadEntityAttachments.js";

const router = Router();

// ===========================================================================
// Rutas sin :id — deben ir ANTES de /:id para evitar colisiones
// ===========================================================================

// Export (GET — antes de /:id para evitar colisión)
router.get("/export", asyncHandler(controller.exportEntities));

// Bulk Import (legacy)
router.post("/bulk-import", asyncHandler(controller.bulkImport));

// Bulk Delete (máx. 100 IDs)
router.post("/bulk-delete", asyncHandler(controller.bulkDelete));

// Import v2
router.post("/import/preview", asyncHandler(controller.importPreview));
router.post("/import/commit",  asyncHandler(controller.importCommit));

// Merge preview / execute
router.get( "/merge-preview/:id/:targetId", asyncHandler(controller.getMergePreview));
router.post("/merge-into/:id/:targetId",    asyncHandler(controller.mergeInto));

// ===========================================================================
// Entity CRUD
// ===========================================================================
router.get(   "/",    asyncHandler(controller.list));
router.post(  "/",    asyncHandler(controller.create));
router.get(   "/:id", asyncHandler(controller.getOne));
router.put(   "/:id", asyncHandler(controller.update));
router.patch( "/:id/toggle", asyncHandler(controller.toggle));
router.delete("/:id", asyncHandler(controller.remove));

// ===========================================================================
// Avatar
// ===========================================================================
router.patch("/:id/avatar", ...uploadEntityAvatarMiddleware, asyncHandler(controller.updateAvatar));

// ===========================================================================
// Addresses
// ===========================================================================
router.get(   "/:id/addresses",                        asyncHandler(controller.listAddresses));
router.post(  "/:id/addresses",                        asyncHandler(controller.createAddress));
router.put(   "/:id/addresses/:addressId",             asyncHandler(controller.updateAddress));
router.delete("/:id/addresses/:addressId",             asyncHandler(controller.removeAddress));
router.patch( "/:id/addresses/:addressId/set-default", asyncHandler(controller.setDefaultAddress));

// ===========================================================================
// Contacts
// ===========================================================================
router.get(   "/:id/contacts",                          asyncHandler(controller.listContacts));
router.post(  "/:id/contacts",                          asyncHandler(controller.createContact));
router.put(   "/:id/contacts/:contactId",               asyncHandler(controller.updateContact));
router.delete("/:id/contacts/:contactId",               asyncHandler(controller.removeContact));
router.patch( "/:id/contacts/:contactId/set-primary",   asyncHandler(controller.setPrimaryContact));

// ===========================================================================
// Attachments
// ===========================================================================
router.get(   "/:id/attachments",                       asyncHandler(controller.listAttachments));
router.post(  "/:id/attachments", ...uploadEntityAttachmentMiddleware, asyncHandler(controller.addAttachment));
router.patch( "/:id/attachments/:attachmentId",         asyncHandler(controller.updateAttachmentLabel));
router.delete("/:id/attachments/:attachmentId",         asyncHandler(controller.removeAttachment));

// ===========================================================================
// Commercial Rules
// ===========================================================================
router.get(   "/:id/rules",               asyncHandler(controller.listRules));
router.post(  "/:id/rules",               asyncHandler(controller.createRule));
router.put(   "/:id/rules/:ruleId",       asyncHandler(controller.updateRule));
router.patch( "/:id/rules/:ruleId/toggle",asyncHandler(controller.toggleRule));
router.delete("/:id/rules/:ruleId",       asyncHandler(controller.removeRule));

// ===========================================================================
// Tax Overrides
// ===========================================================================
router.get(   "/:id/tax-overrides",              asyncHandler(controller.listTaxOverrides));
router.put(   "/:id/tax-overrides",              asyncHandler(controller.upsertTaxOverride));
router.delete("/:id/tax-overrides/:overrideId",  asyncHandler(controller.removeTaxOverride));

// ===========================================================================
// Merma Overrides
// ===========================================================================
router.get(   "/:id/merma-overrides",             asyncHandler(controller.listMermaOverrides));
router.put(   "/:id/merma-overrides",             asyncHandler(controller.upsertMermaOverride));
router.delete("/:id/merma-overrides/:overrideId", asyncHandler(controller.removeMermaOverride));

// ===========================================================================
// Entity Relations
// ===========================================================================
router.get(   "/:id/relations",             asyncHandler(controller.listRelations));
router.post(  "/:id/relations",             asyncHandler(controller.addRelation));
router.delete("/:id/relations/:relationId", asyncHandler(controller.removeRelation));

export default router;
