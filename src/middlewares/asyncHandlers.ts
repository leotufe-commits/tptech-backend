// tptech-backend/src/middlewares/asyncHandler.ts
import type { RequestHandler } from "express";

export const asyncHandler =
  (fn: any): RequestHandler =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);