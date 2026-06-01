// tptech-backend/src/routes/index.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

/* =====================
   AUTH (público)
===================== */
import authRoutes from "../modules/auth/auth.routes.js";

/* =====================
   MÓDULOS
===================== */
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import usersRoutes from "../modules/users/users.routes.js";
import valuationRoutes from "../modules/valuation/valuation.routes.js";
import companyRoutes from "../modules/company/company.routes.js";
import rolesRoutes from "../modules/roles/roles.routes.js";
import storageRoutes from "../modules/storage/storage.routes.js";
import catalogsRoutes from "../modules/catalogs/catalogs.routes.js";
import permissionsRoutes from "../modules/permissions/permissions.routes.js";
import warehousesRoutes from "../modules/warehouses/warehouses.routes.js";
import categoriesRoutes from "../modules/categories/categories.routes.js";
import taxesRoutes from "../modules/taxes/taxes.routes.js";
import paymentsRoutes from "../modules/payments/payments.routes.js";
import shippingRoutes from "../modules/shipping/shipping.routes.js";
import sellersRoutes from "../modules/sellers/sellers.routes.js";
import priceListsRoutes from "../modules/price-lists/price-lists.routes.js";
import attributeDefsRoutes from "../modules/attribute-defs/attribute-defs.routes.js";
import commercialEntitiesRoutes from "../modules/commercial-entities/commercial-entities.routes.js";
import articlesRoutes from "../modules/articles/articles.routes.js";
import articleMovementsRoutes from "../modules/article-movements/article-movements.routes.js";
import salesRoutes from "../modules/sales/sales.routes.js";
import promotionsRoutes from "../modules/promotions/promotions.routes.js";
import quantityDiscountsRoutes from "../modules/quantity-discounts/quantity-discounts.routes.js";
import labelTemplatesRouter  from "../modules/label-templates/label-templates.routes.js";
import printerProfilesRouter from "../modules/printer-profiles/printer-profiles.routes.js";
import purchasesRoutes from "../modules/purchases/purchases.routes.js";
import crossSettlementsRoutes from "../modules/cross-settlements/cross-settlements.routes.js";
import articleGroupsRoutes from "../modules/article-groups/article-groups.routes.js";
import documentTemplatesRoutes from "../modules/document-templates/document-templates.routes.js";
import importBatchesRoutes from "../modules/import-batches/import-batches.routes.js";
import salesChannelsRoutes from "../modules/sales-channels/sales-channels.routes.js";
import couponsRoutes from "../modules/coupons/coupons.routes.js";
import receiptsRoutes from "../modules/receipts/receipts.routes.js";
import receiptSeriesRoutes from "../modules/receipt-series/receipt-series.routes.js";
import unitsRoutes from "../modules/units/units.routes.js";
import userPreferencesRoutes from "../modules/user-preferences/user-preferences.routes.js";

/* =====================
   ✅ DASHBOARD
===================== */
import dashboardRoutes from "../modules/dashboard/dashboard.routes.js";

const router = Router();

/* =====================
   PÚBLICO
===================== */
router.use("/auth", authRoutes);

/* =====================
   STORAGE
===================== */
router.use("/storage", requireAuth, storageRoutes);

/* =====================
   PRIVADO
===================== */
router.use("/movimientos", requireAuth, movimientosRoutes);
router.use("/users", requireAuth, usersRoutes);
router.use("/user-preferences", requireAuth, userPreferencesRoutes);
router.use("/company", requireAuth, companyRoutes);
router.use("/roles", requireAuth, rolesRoutes);
router.use("/warehouses", requireAuth, warehousesRoutes);
router.use("/categories", requireAuth, categoriesRoutes);
router.use("/taxes", requireAuth, taxesRoutes);
router.use("/payments", requireAuth, paymentsRoutes);
router.use("/shipping", requireAuth, shippingRoutes);
router.use("/sellers", requireAuth, sellersRoutes);
router.use("/price-lists", requireAuth, priceListsRoutes);
router.use("/attribute-defs", requireAuth, attributeDefsRoutes);
router.use("/commercial-entities", requireAuth, commercialEntitiesRoutes);
router.use("/articles", requireAuth, articlesRoutes);
router.use("/article-movements", requireAuth, articleMovementsRoutes);
router.use("/sales", requireAuth, salesRoutes);
router.use("/promotions", requireAuth, promotionsRoutes);
router.use("/quantity-discounts", requireAuth, quantityDiscountsRoutes);
router.use("/label-templates",  labelTemplatesRouter);
router.use("/printer-profiles", printerProfilesRouter);
router.use("/purchases", requireAuth, purchasesRoutes);
router.use("/cross-settlements", requireAuth, crossSettlementsRoutes);
router.use("/article-groups",       requireAuth, articleGroupsRoutes);
router.use("/document-templates",   requireAuth, documentTemplatesRoutes);
router.use("/import-batches",       requireAuth, importBatchesRoutes);
router.use("/sales-channels",       requireAuth, salesChannelsRoutes);
router.use("/coupons",             requireAuth, couponsRoutes);
router.use("/receipts",            requireAuth, receiptsRoutes);
router.use("/receipt-series",      requireAuth, receiptSeriesRoutes);

/**
 * Catalogs
 * Base: /company/catalogs
 */
router.use("/company/catalogs", requireAuth, catalogsRoutes);

/**
 * Units (Fase 3 — entidad unificada de unidades)
 * Base: /company/units
 */
router.use("/company/units", requireAuth, unitsRoutes);

/**
 * Permissions
 * Base: /permissions
 */
router.use("/permissions", requireAuth, permissionsRoutes);

// valuation ya aplica requireAuth internamente
router.use("/valuation", valuationRoutes);

/* =====================
   ✅ DASHBOARD (privado)
   Base: /dashboard
===================== */
router.use("/dashboard", requireAuth, dashboardRoutes);

export default router;