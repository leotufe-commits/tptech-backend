// src/modules/purchases/purchases.routes.ts
import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as ctrl from "./purchases.controller.js";

const router = Router();

// ── Compras ──────────────────────────────────────────────────────────────────
router.get("/",                asyncHandler(ctrl.list));
router.post("/",               asyncHandler(ctrl.create));
router.get("/:id",             asyncHandler(ctrl.getOne));
router.post("/:id/confirm",    asyncHandler(ctrl.confirm));
router.post("/:id/cancel",     asyncHandler(ctrl.cancel));

// ── Pagos por proveedor ───────────────────────────────────────────────────────
router.get("/suppliers/:supplierId/payments",         asyncHandler(ctrl.listPayments));
router.post("/suppliers/:supplierId/payments",        asyncHandler(ctrl.registerPayment));
router.post("/suppliers/:supplierId/metal-returns",   asyncHandler(ctrl.registerMetalReturn));
router.post("/suppliers/:supplierId/apply-credit",    asyncHandler(ctrl.applyCredit));
router.post("/payments/:paymentId/void",              asyncHandler(ctrl.voidPayment));

export default router;
