import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./article-groups.controller.js";
import { uploadGroupImageMiddleware } from "../../middlewares/uploadGroupImage.js";

const router = Router();

router.get("/",              asyncHandler(controller.list));
router.post("/",             asyncHandler(controller.create));
router.get("/:id",           asyncHandler(controller.getOne));
router.put("/:id",           asyncHandler(controller.update));
router.patch("/:id/toggle",  asyncHandler(controller.toggle));
router.delete("/:id",        asyncHandler(controller.remove));

// Gestión de items del grupo (variantes + artículos simples)
router.get("/:id/available-items",                          asyncHandler(controller.searchAvailable));
router.get("/:id/available-items/tree",                     asyncHandler(controller.searchAvailableTree));
router.post("/:id/items/batch",                             asyncHandler(controller.addItemsBatch));
router.post("/:id/items",                                   asyncHandler(controller.addItem));
router.patch("/:id/items/:itemId/selector-value",           asyncHandler(controller.updateSelectorValue));
router.delete("/:id/items/:itemId",                         asyncHandler(controller.removeItem));
router.put("/:id/items/reorder",                            asyncHandler(controller.reorderItems));

// Gestión de imágenes del grupo
router.get("/:id/images",                       asyncHandler(controller.listImages));
router.post("/:id/images",                      [...uploadGroupImageMiddleware, asyncHandler(controller.addImage)]);
router.patch("/:id/images/:imageId/set-main",   asyncHandler(controller.setMainImage));
router.delete("/:id/images/:imageId",           asyncHandler(controller.removeImage));

export default router;
