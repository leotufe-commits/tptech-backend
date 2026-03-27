import { PrismaClient } from '@prisma/client';
const p = new PrismaClient();
const r = await p.$queryRaw`SELECT column_name FROM information_schema.columns WHERE table_name = 'Article' AND column_name = 'useManualSalePrice'`;
console.log('Column exists in DB:', JSON.stringify(r));
await p.$disconnect();
