// src/modules/receipt-series/receipt-series.routes.ts
// ============================================================================
// Rutas REST admin de ReceiptSeries — Etapa A (2026-05-29).
//
// Montaje en `routes/index.ts`:
//   router.use("/receipt-series", requireAuth, receiptSeriesRoutes);
//
// Endpoints:
//   GET    /                listar series del tenant
//   GET    /:id             detalle de una serie
//   POST   /                crear serie
//   PATCH  /:id             editar (name, prefix, pointOfSale, nextNumber, isActive)
//   DELETE /:id             soft-delete (bloqueado si tiene receipts emitidos)
// ============================================================================

import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { validateBody } from "../../middlewares/validate.js";
import * as controller from "./receipt-series.controller.js";
import {
  createReceiptSeriesSchema,
  updateReceiptSeriesSchema,
} from "./receipt-series.schemas.js";

const router = Router();

router.get("/", asyncHandler(controller.list));
router.get("/:id", asyncHandler(controller.getOne));
router.post(
  "/",
  validateBody(createReceiptSeriesSchema),
  asyncHandler(controller.create),
);
router.patch(
  "/:id",
  validateBody(updateReceiptSeriesSchema),
  asyncHandler(controller.update),
);
router.delete("/:id", asyncHandler(controller.remove));

export default router;
