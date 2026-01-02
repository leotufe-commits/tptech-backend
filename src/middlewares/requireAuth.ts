import { Request, Response, NextFunction } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("❌ JWT_SECRET no está definido en las variables de entorno");
}

declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
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
    next();
  } catch (err) {
    console.error("🔒 AUTH ERROR:", err);
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
}
