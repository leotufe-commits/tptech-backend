// src/modules/receipts/receipts.routes.ts
import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./receipts.controller.js";

const router = Router();

router.post("/", asyncHandler(controller.createDraft));

export default router;
