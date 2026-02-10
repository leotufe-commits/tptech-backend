// tptech-backend/src/routes/catalogs.routes.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

import {
  listCatalog,
  createCatalogItem,
  bulkCreateCatalogItems,
  updateCatalogItem,
  setCatalogItemFavorite, // ✅ NUEVO
} from "../controllers/catalogs.controller.js";

const router = Router();

/**
 * Base: /company/catalogs
 * - GET    /:type
 * - POST   /:type
 * - POST   /:type/bulk
 * - PATCH  /item/:id
 * - PATCH  /item/:id/favorite ✅
 */
router.get("/:type", requireAuth, listCatalog);
router.post("/:type", requireAuth, createCatalogItem);
router.post("/:type/bulk", requireAuth, bulkCreateCatalogItems);
router.patch("/item/:id", requireAuth, updateCatalogItem);

// ✅ Favorito (1 por type)
router.patch("/item/:id/favorite", requireAuth, setCatalogItemFavorite);

export default router;
