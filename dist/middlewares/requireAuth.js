"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireAuth = requireAuth;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
function requireAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ message: "No autorizado" });
        }
        const [type, token] = authHeader.split(" ");
        if (type !== "Bearer" || !token) {
            return res.status(401).json({ message: "Token inválido" });
        }
        const payload = jsonwebtoken_1.default.verify(token, JWT_SECRET);
        if (!payload.sub) {
            return res.status(401).json({ message: "Token inválido" });
        }
        req.userId = payload.sub;
        next();
    }
    catch {
        return res.status(401).json({ message: "Token inválido o expirado" });
    }
}
