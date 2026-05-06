// src/modules/import-batches/import-batches.routes.ts
import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./import-batches.controller.js";

const router = Router();

// GET /api/import-batches?entityType=ARTICLE&status=PARTIAL&page=1&pageSize=20
router.get("/",          asyncHandler(controller.listBatches));

// GET /api/import-batches/:id
router.get("/:id",       asyncHandler(controller.getBatch));

// GET /api/import-batches/:id/rows?actionResult=FAILED&page=1
router.get("/:id/rows",  asyncHandler(controller.listBatchRows));

// GET /api/import-batches/:id/errors.csv  — descarga CSV con filas fallidas
router.get("/:id/errors.csv", asyncHandler(controller.exportErrors));

// POST /api/import-batches/:id/retry-errors — reintenta solo las filas FAILED
router.post("/:id/retry-errors", asyncHandler(controller.retryErrors));

export default router;
