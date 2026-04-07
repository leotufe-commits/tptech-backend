import { Router } from "express";
import { asyncHandler } from "../../middlewares/asyncHandlers.js";
import * as controller from "./article-groups.controller.js";

const router = Router();

router.get("/",              asyncHandler(controller.list));
router.post("/",             asyncHandler(controller.create));
router.get("/:id",           asyncHandler(controller.getOne));
router.put("/:id",           asyncHandler(controller.update));
router.patch("/:id/toggle",  asyncHandler(controller.toggle));
router.delete("/:id",        asyncHandler(controller.remove));

// Gestión de artículos del grupo
router.get("/:id/available-articles",           asyncHandler(controller.searchAvailable));
router.post("/:id/articles",                    asyncHandler(controller.addArticle));
router.delete("/:id/articles/:articleId",       asyncHandler(controller.removeArticle));
router.put("/:id/articles/reorder",             asyncHandler(controller.reorderArticles));

export default router;
