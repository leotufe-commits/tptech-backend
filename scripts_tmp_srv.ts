import "dotenv/config";
import express from "express";
import receiptsRoutes from "./src/modules/receipts/receipts.routes.js";
const JID = "cmp4tnn0c0000mwcav9t7ab22";
const app = express();
app.use((req: any, _res, next) => { req.user = { jewelryId: JID, id: "u_repro", email: "repro@test" }; next(); });
app.use("/receipts", receiptsRoutes);
app.use((err: any, _req: any, res: any, _next: any) => {
  console.error("ERRH >>>", err?.constructor?.name, "| code:", err?.code, "| status:", err?.status, "| msg:", err?.message);
  if (err?.stack) console.error(err.stack.split("\n").slice(0,6).join("\n"));
  res.status(err?.status || 500).json({ message: err?.message || "Error interno" });
});
app.listen(3999, "127.0.0.1", () => console.log("READY :3999"));
