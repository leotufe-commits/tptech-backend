import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

type JwtPayload = {
  sub: string;
  iat?: number;
  exp?: number;
};

declare global {
  namespace Express {
    interface Request {
      userId?: string;
    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ message: "No autorizado" });
    }

    const [type, token] = authHeader.split(" ");

    if (type !== "Bearer" || !token) {
      return res.status(401).json({ message: "Token inválido" });
    }

    const payload = jwt.verify(token, JWT_SECRET) as JwtPayload;

    if (!payload.sub) {
      return res.status(401).json({ message: "Token inválido" });
    }

    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido o expirado" });
  }
}
