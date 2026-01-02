import type { Request, Response, NextFunction } from "express";
import jwt, { type JwtPayload } from "jsonwebtoken";

/**
 * Extensión del Request de Express
 */
declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

/**
 * Middleware de autenticación JWT
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const JWT_SECRET = process.env.JWT_SECRET;

  if (!JWT_SECRET) {
    return res.status(500).json({
      message: "JWT_SECRET no está definido en el servidor"
    });
  }

  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ message: "No autorizado (sin token)" });
    }

    const [type, token] = authHeader.split(" ");

    if (type !== "Bearer" || !token) {
      return res.status(401).json({ message: "Formato de token inválido" });
    }

    const payload = jwt.verify(token, JWT_SECRET) as JwtPayload;

    if (!payload.sub || typeof payload.sub !== "string") {
      return res.status(401).json({ message: "Token inválido" });
    }

    req.userId = payload.sub;
    return next();
  } catch (error) {
    console.error("🔒 AUTH ERROR:", error);
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
}
