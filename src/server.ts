// src/server.ts
import dotenv from "dotenv";
import { createApp } from "./app.js";
import { getEnv } from "./config/env.js";

dotenv.config();

const env = getEnv();

const app = createApp();

app.listen(env.PORT, "0.0.0.0", () => {
  console.log(`🚀 Backend running on port ${env.PORT}`);
});
