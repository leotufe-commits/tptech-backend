// tptech-backend/src/routes/catalogs.routes.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

import {
  listCatalog,
  createCatalogItem,
  bulkCreateCatalogItems,
  updateCatalogItem,
} from "../controllers/catalogs.controller.js";

const router = Router();

/**
 * Base: /company/catalogs
 * - GET    /:type
 * - POST   /:type
 * - POST   /:type/bulk
 * - PATCH  /item/:id
 */
router.get("/:type", requireAuth, listCatalog);
router.post("/:type", requireAuth, createCatalogItem);
router.post("/:type/bulk", requireAuth, bulkCreateCatalogItems);
router.patch("/item/:id", requireAuth, updateCatalogItem);

export default router;
