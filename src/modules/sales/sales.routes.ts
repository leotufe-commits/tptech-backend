import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./sales.controller.js";

const router = Router();

router.post("/preview", asyncHandler(controller.previewSale));
router.get("/", asyncHandler(controller.list));
router.post("/", asyncHandler(controller.create));
router.get("/caja", asyncHandler(controller.cajaSummary));
router.get("/:id", asyncHandler(controller.getOne));
router.put("/:id", asyncHandler(controller.update));
router.post("/:id/confirm", asyncHandler(controller.confirm));
router.post("/:id/payments", asyncHandler(controller.addPayment));
router.patch("/:id/cancel", asyncHandler(controller.cancel));
// 1.B — Descarga del PDF oficial del comprobante. Requiere venta confirmada
// (DRAFT → 409 SALE_NOT_CONFIRMED, CANCELLED → 409 SALE_CANCELLED). Lee
// snapshot + Receipt.code + DocumentTemplate FACTURA y devuelve un PDF.
router.get("/:id/pdf", asyncHandler(controller.downloadPdf));
// 1.D — Envia el PDF oficial por mail al destinatario indicado.
// Body: { to, subject, message }. Mismas reglas de estado que /pdf +
// 409 SALE_WITHOUT_RECEIPT_NUMBER si no hay Receipt.code.
router.post("/:id/send-email", asyncHandler(controller.sendEmail));

export default router;
