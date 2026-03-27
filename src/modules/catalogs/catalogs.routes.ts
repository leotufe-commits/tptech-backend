// tptech-backend/src/modules/catalogs/catalogs.routes.ts
import { Router } from "express";

import {
  listCatalog,
  createCatalogItem,
  bulkCreateCatalogItems,
  updateCatalogItem,
  setCatalogItemFavorite,
  deleteCatalogItem,
} from "./catalogs.controller.js";

const router = Router();

/**
 * Base (lo monta routes/index.ts):
 * /company/catalogs
 */
router.get("/:type", listCatalog);
router.post("/:type", createCatalogItem);
router.post("/:type/bulk", bulkCreateCatalogItems);
router.patch("/item/:id", updateCatalogItem);
router.patch("/item/:id/favorite", setCatalogItemFavorite);
router.delete("/item/:id", deleteCatalogItem);

export default router;