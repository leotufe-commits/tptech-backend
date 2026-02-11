// tptech-backend/src/types/express.d.ts
import "express-serve-static-core";

declare module "express-serve-static-core" {
  interface Request {
    // auth context
    userId?: string;
    tenantId?: string;

    // permisos efectivos (requireAuth)
    permissions?: string[];

    // roles efectivos (requireAuth)
    roles?: string[];
    isOwner?: boolean;
  }
}

export {};
