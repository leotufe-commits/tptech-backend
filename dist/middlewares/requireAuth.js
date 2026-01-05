import jwt, {} from "jsonwebtoken";
import { prisma, setContextTenantId, setContextUserId } from "../lib/prisma.js";
import { UserStatus } from "@prisma/client";
/**
 * Middleware de autenticación JWT + carga de contexto multi-tenant
 */
export async function requireAuth(req, res, next) {
    const JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
        return res.status(500).json({ message: "JWT_SECRET no está definido en el servidor" });
    }
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader)
            return res.status(401).json({ message: "No autorizado (sin token)" });
        const [type, token] = authHeader.split(" ");
        if (type !== "Bearer" || !token) {
            return res.status(401).json({ message: "Formato de token inválido" });
        }
        const payload = jwt.verify(token, JWT_SECRET);
        if (!payload.sub || typeof payload.sub !== "string") {
            return res.status(401).json({ message: "Token inválido" });
        }
        const userId = payload.sub;
        // Buscar usuario real (y su tenant)
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { id: true, status: true, jewelryId: true },
        });
        if (!user)
            return res.status(401).json({ message: "Usuario no encontrado" });
        if (user.status !== UserStatus.ACTIVE) {
            return res.status(403).json({ message: "Usuario no habilitado" });
        }
        // Setear request + ALS context
        req.userId = user.id;
        req.tenantId = user.jewelryId;
        // ✅ OJO: sin "Id" al final en el nombre de la función
        setContextUserId(user.id);
        setContextTenantId(user.jewelryId);
        return next();
    }
    catch (error) {
        console.error("🔒 AUTH ERROR:", error);
        return res.status(401).json({ message: "Token inválido o expirado" });
    }
}
//# sourceMappingURL=requireAuth.js.map