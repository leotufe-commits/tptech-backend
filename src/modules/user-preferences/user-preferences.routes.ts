import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import { validateBody } from "../../middlewares/validate.js";
import * as controller from "./user-preferences.controller.js";
import { updatePreferenceSchema } from "./user-preferences.schemas.js";

const router = Router();

router.get("/me", asyncHandler(controller.getMe));
router.put("/me", validateBody(updatePreferenceSchema), asyncHandler(controller.updateMe));

export default router;
