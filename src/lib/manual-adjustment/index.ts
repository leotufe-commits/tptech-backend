// src/lib/manual-adjustment/index.ts
// =============================================================================
// Barrel del módulo Manual Adjustment.
// =============================================================================

export type {
  ManualAdjustmentScope,
  ManualAdjustmentInput,
  ManualAdjustmentInputUnified,
  ManualAdjustmentInputBreakdown,
  ManualAdjustmentMetalInput,
  ManualAdjustmentAudit,
  ManualAdjustmentSnapshot,
  ManualAdjustmentSnapshotUnified,
  ManualAdjustmentSnapshotBreakdown,
  ManualAdjustmentSnapshotMetalEntry,
  ManualAdjustmentSnapshotMonetaryLayer,
  ManualAdjustmentSnapshotTotals,
  ManualAdjustmentPreview,
  ManualAdjustmentBreakdownContext,
  ManualAdjustmentMetalContextItem,
} from "./types.js";

export { buildManualAdjustmentSnapshot } from "./buildSnapshot.js";
export {
  sanitizeManualAdjustmentInput,
  MANUAL_ADJUSTMENT_EPS_MONEY,
  MANUAL_ADJUSTMENT_EPS_GRAMS,
} from "./sanitize.js";
