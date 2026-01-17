import "dotenv/config";
import { defineConfig } from "prisma/config";

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is missing in environment");
}

export default defineConfig({
  schema: "prisma/schema.prisma",
  datasource: {
    db: {
      url: DATABASE_URL,
    },
  },
});
