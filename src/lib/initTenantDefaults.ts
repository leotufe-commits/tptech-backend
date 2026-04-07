// src/lib/initTenantDefaults.ts
//
// Shared logic for initializing system roles, permissions and catalog defaults
// for a new tenant. Used by: auth.controller.ts (register) and prisma/seed.ts
//
import { PermModule, PermAction } from "@prisma/client";
import type { Prisma } from "@prisma/client";

// Precios de referencia iniciales en moneda base (ARS / gramo)
const ORO_REF_VALUE     = 250_000;
const PLATA_REF_VALUE   =   1_800;
const PLATINO_REF_VALUE = 230_000;

const ALL_MODULES = Object.values(PermModule) as PermModule[];
const ALL_ACTIONS = Object.values(PermAction) as PermAction[];

function pick(permIdByKey: Map<string, string>, modules: PermModule[], actions: PermAction[]): string[] {
  const ids: string[] = [];
  for (const m of modules)
    for (const a of actions) {
      const id = permIdByKey.get(`${m}:${a}`);
      if (id) ids.push(id);
    }
  return ids;
}

/* ============================================================
   PRIVATE HELPERS — categorías y atributos
============================================================ */

/**
 * Ensures an ArticleCategory exists for the tenant.
 * Idempotent: returns existing id if already present.
 */
async function ensureCategory(
  db: any,
  jewelryId: string,
  name: string,
  parentId?: string,
  sortOrder = 0
): Promise<string> {
  const existing = await db.articleCategory.findFirst({
    where: { jewelryId, name, deletedAt: null },
    select: { id: true },
  });
  if (existing) return existing.id;

  const cat = await db.articleCategory.create({
    data: { jewelryId, name, parentId: parentId ?? null, sortOrder, isActive: true },
    select: { id: true },
  });
  return cat.id;
}

/**
 * Ensures an ArticleAttributeDef exists for the tenant.
 * If it doesn't exist, creates it with all its options.
 * Idempotent by code.
 */
async function ensureAttributeDef(
  db: any,
  jewelryId: string,
  def: {
    code: string;
    name: string;
    inputType: string;
    options: (string | { label: string; codeExtension?: string })[];
  }
): Promise<string> {
  const existing = await db.articleAttributeDef.findFirst({
    where: { jewelryId, code: def.code, deletedAt: null },
    select: { id: true },
  });
  if (existing) return existing.id;

  const created = await db.articleAttributeDef.create({
    data: { jewelryId, name: def.name, code: def.code, inputType: def.inputType, isActive: true },
    select: { id: true },
  });

  for (let i = 0; i < def.options.length; i++) {
    const opt = def.options[i];
    const label = typeof opt === "string" ? opt : opt.label;
    const codeExtension = typeof opt === "string" ? "" : (opt.codeExtension ?? "");
    await db.articleAttributeDefOption.create({
      data: {
        definitionId: created.id,
        label,
        value: label,
        codeExtension,
        sortOrder: i,
        isActive: true,
      },
    });
  }

  return created.id;
}

/**
 * Assigns an attribute definition to a category.
 * Idempotent: skips if already assigned.
 */
async function ensureAttributeAssignment(
  db: any,
  jewelryId: string,
  categoryId: string,
  definitionId: string,
  sortOrder = 0,
  inheritToChild = true,
  isVariantAxis = true
): Promise<void> {
  const existing = await db.articleCategoryAttribute.findFirst({
    where: { jewelryId, categoryId, definitionId, deletedAt: null },
    select: { id: true },
  });
  if (existing) return;

  await db.articleCategoryAttribute.create({
    data: {
      jewelryId,
      categoryId,
      definitionId,
      inheritToChild,
      isVariantAxis,
      isActive: true,
      isFilterable: true,
      sortOrder,
    },
  });
}

/**
 * Creates the simplified jewelry category taxonomy for a tenant.
 * Returns a map of { parentName → parentId, childName → childId }.
 */
async function ensureJewelryCategories(
  db: any,
  jewelryId: string
): Promise<Record<string, string>> {
  const TAXONOMY: {
    name: string;
    sortOrder: number;
    children: { name: string; sortOrder: number }[];
  }[] = [
    {
      name: "Anillos", sortOrder: 0,
      children: [
        { name: "Anillo sin piedras",  sortOrder: 0 },
        { name: "Anillos con piedras", sortOrder: 1 },
        { name: "Anillos sellos",      sortOrder: 2 },
      ],
    },
    {
      name: "Cadenas", sortOrder: 1,
      children: [
        { name: "Cadenas huecas",      sortOrder: 0 },
        { name: "Cadenas maquinadas",  sortOrder: 1 },
      ],
    },
  ];

  const ids: Record<string, string> = {};

  for (const parent of TAXONOMY) {
    const parentId = await ensureCategory(db, jewelryId, parent.name, undefined, parent.sortOrder);
    ids[parent.name] = parentId;

    for (const child of parent.children) {
      const childId = await ensureCategory(db, jewelryId, child.name, parentId, child.sortOrder);
      ids[child.name] = childId;
    }
  }

  return ids;
}

/**
 * Creates attribute definitions and assigns them to specific categories.
 *
 * COLOR_ORO → Anillos (inheritToChild: true) + Cadenas (inheritToChild: true)
 * COLOR_GEMAS → "Anillos con piedras" subcategory (inheritToChild: false)
 */
async function ensureJewelryAttributes(
  db: any,
  jewelryId: string,
  categoryIds: Record<string, string>
): Promise<void> {
  const ATTR_COLOR_ORO = await ensureAttributeDef(db, jewelryId, {
    code: "COLOR_ORO",
    name: "Color de Oro",
    inputType: "SELECT",
    options: [
      { label: "Oro Amarillo 18Kts", codeExtension: "A" },
      { label: "Oro Blanco 18Kts",   codeExtension: "B" },
      { label: "Oro Rojo 18Kts",     codeExtension: "R" },
    ],
  });

  const ATTR_COLOR_GEMAS = await ensureAttributeDef(db, jewelryId, {
    code: "COLOR_GEMAS",
    name: "Color de Gemas",
    inputType: "SELECT",
    options: [
      { label: "Cubic Zirconia", codeExtension: "CZ" },
      { label: "Zafiro",         codeExtension: "ZF" },
      { label: "Esmeralda",      codeExtension: "ES" },
      { label: "Rubi",           codeExtension: "RB" },
    ],
  });

  const ATTR_LARGO = await ensureAttributeDef(db, jewelryId, {
    code: "LARGO",
    name: "Largo",
    inputType: "SELECT",
    options: [
      { label: "40 cm.", codeExtension: "40" },
      { label: "45 cm.", codeExtension: "45" },
      { label: "50 cm.", codeExtension: "50" },
      { label: "55 cm.", codeExtension: "55" },
      { label: "60 cm.", codeExtension: "60" },
    ],
  });

  // COLOR_ORO → Anillos y Cadenas (se hereda a subcategorías)
  for (const parentName of ["Anillos", "Cadenas"]) {
    if (categoryIds[parentName]) {
      await ensureAttributeAssignment(db, jewelryId, categoryIds[parentName], ATTR_COLOR_ORO, 0, true);
    }
  }

  // COLOR_GEMAS → solo "Anillos con piedras"
  if (categoryIds["Anillos con piedras"]) {
    await ensureAttributeAssignment(db, jewelryId, categoryIds["Anillos con piedras"], ATTR_COLOR_GEMAS, 0, false);
  }

  // LARGO → Cadenas (se hereda a subcategorías)
  if (categoryIds["Cadenas"]) {
    await ensureAttributeAssignment(db, jewelryId, categoryIds["Cadenas"], ATTR_LARGO, 1, true);
  }
}

/**
 * Creates the 3 base currencies for a new tenant.
 * ARS (base), USD, EUR — all idempotent by code.
 * Returns the ARS currency id (needed for metal quote snapshots).
 */
async function ensureCurrencies(db: any, jewelryId: string): Promise<string> {
  const now = new Date();

  // ── ARS (moneda base) ────────────────────────────────────────────────────
  // upsert en @@unique([jewelryId, code]) — cubre también registros soft-deleted
  // update restores deletedAt/isBase en caso de que el registro haya sido borrado
  const ars = await db.currency.upsert({
    where: { jewelryId_code: { jewelryId, code: "ARS" } },
    create: { jewelryId, code: "ARS", name: "Peso Argentino", symbol: "AR$", isBase: true,  isActive: true },
    update: { deletedAt: null, isBase: true, isActive: true },
    select: { id: true },
  });
  const arsId: string = ars.id;

  // ── USD ──────────────────────────────────────────────────────────────────
  const usd = await db.currency.upsert({
    where: { jewelryId_code: { jewelryId, code: "USD" } },
    create: { jewelryId, code: "USD", name: "Dólares", symbol: "US$", isBase: false, isActive: true },
    update: { deletedAt: null, isActive: true },
    select: { id: true, createdAt: true, updatedAt: true },
  });
  // Crear rate solo si la moneda acaba de ser creada (no tiene rates previos)
  const usdRateCount = await db.currencyRate.count({ where: { currencyId: usd.id } });
  if (usdRateCount === 0) {
    await db.currencyRate.create({ data: { currencyId: usd.id, rate: "1500", effectiveAt: now } });
  }

  // ── EUR ──────────────────────────────────────────────────────────────────
  const eur = await db.currency.upsert({
    where: { jewelryId_code: { jewelryId, code: "EUR" } },
    create: { jewelryId, code: "EUR", name: "Euro", symbol: "€", isBase: false, isActive: true },
    update: { deletedAt: null, isActive: true },
    select: { id: true },
  });
  const eurRateCount = await db.currencyRate.count({ where: { currencyId: eur.id } });
  if (eurRateCount === 0) {
    await db.currencyRate.create({ data: { currencyId: eur.id, rate: "1800", effectiveAt: now } });
  }

  return arsId;
}

/**
 * Crea un metal con sus variantes para el tenant.
 * También inicializa MetalRefValueHistory, MetalVariantValueHistory y MetalQuote en moneda base.
 * Idempotente: omite el metal si ya existe (jewelryId, name); omite variantes por sku.
 */
async function ensureMetalWithVariants(
  db: any,
  jewelryId: string,
  baseCurrencyId: string,
  config: {
    name: string;
    symbol: string;
    referenceValue: number;
    sortOrder: number;
    variants: { name: string; sku: string; purity: number; saleFactor: number }[];
  }
): Promise<void> {
  const now = new Date();
  const refValue = String(config.referenceValue);

  // Buscar sin filtrar deletedAt: @@unique([jewelryId, name]) no incluye deletedAt.
  const existingMetal = await db.metal.findFirst({
    where: { jewelryId, name: config.name },
    select: { id: true },
  });

  let metalId: string;
  if (existingMetal) {
    metalId = existingMetal.id;
  } else {
    const metal = await db.metal.create({
      data: {
        jewelryId,
        name:           config.name,
        symbol:         config.symbol,
        referenceValue: refValue,
        sortOrder:      config.sortOrder,
        isActive:       true,
      },
      select: { id: true },
    });
    metalId = metal.id;

    await db.metalRefValueHistory.create({
      data: { jewelryId, metalId, referenceValue: refValue, effectiveAt: now },
    });
  }

  // finalSalePrice = referenceValue × purity × saleFactor (redondeado a 2 dec)
  for (const v of config.variants) {
    const existingVariant = await db.metalVariant.findFirst({
      where: { metalId, sku: v.sku },
      select: { id: true },
    });
    if (existingVariant) continue;

    const finalSaleRaw = config.referenceValue * v.purity * v.saleFactor;
    const finalSale    = String(Math.round(finalSaleRaw * 100) / 100);
    const purityStr    = String(v.purity);
    const saleFactorStr = String(v.saleFactor);

    const variant = await db.metalVariant.create({
      data: {
        metalId,
        name:       v.name,
        sku:        v.sku,
        purity:     purityStr,
        saleFactor: saleFactorStr,
        isActive:   true,
        isFavorite: false,
      },
      select: { id: true },
    });

    await db.metalVariantValueHistory.create({
      data: {
        jewelryId,
        metalId,
        variantId:      variant.id,
        referenceValue: refValue,
        purity:         purityStr,
        saleFactor:     saleFactorStr,
        finalSalePrice: finalSale,
        effectiveAt:    now,
      },
    });

    await db.metalQuote.create({
      data: {
        variantId:  variant.id,
        currencyId: baseCurrencyId,
        price:      finalSale,
        effectiveAt: now,
      },
    });
  }
}

/* ============================================================
   PUBLIC API
============================================================ */

/**
 * Ensures all Permission rows exist (global, shared across all tenants).
 * Idempotent — skips duplicates.
 * Returns a Map of "MODULE:ACTION" -> permissionId.
 */
export async function ensureGlobalPermissions(
  db: Prisma.TransactionClient
): Promise<Map<string, string>> {
  const permissionsData = ALL_MODULES.flatMap((module) =>
    ALL_ACTIONS.map((action) => ({ module, action }))
  );

  await db.permission.createMany({ data: permissionsData, skipDuplicates: true });

  const all = await db.permission.findMany();
  const permIdByKey = new Map<string, string>();
  for (const p of all) permIdByKey.set(`${p.module}:${p.action}`, p.id);
  return permIdByKey;
}

/**
 * Idempotent upsert of the 4 system roles for a tenant.
 *
 * - OWNER: permissions are always fully reset to all permissions.
 * - ADMIN / STAFF / READONLY: permissions are only set if the role has none yet
 *   (preserves any custom configuration the user may have made).
 *
 * Returns the ownerRoleId.
 */
export async function ensureSystemRoles(
  db: Prisma.TransactionClient,
  jewelryId: string,
  permIdByKey: Map<string, string>
): Promise<{ ownerRoleId: string }> {
  const OWNER_PERMS = Array.from(permIdByKey.values());
  const ADMIN_PERMS = pick(permIdByKey, ALL_MODULES, ALL_ACTIONS);
  const STAFF_PERMS = pick(permIdByKey, ALL_MODULES, [PermAction.VIEW, PermAction.CREATE, PermAction.EDIT]);
  const READONLY_PERMS = pick(permIdByKey, ALL_MODULES, [PermAction.VIEW]);

  const roleDefs = [
    { name: "OWNER",    displayName: "Propietario",   isSystem: true, permIds: OWNER_PERMS,    forcePerms: true  },
    { name: "ADMIN",    displayName: "Administrador", isSystem: true, permIds: ADMIN_PERMS,    forcePerms: false },
    { name: "STAFF",    displayName: "Vendedor",      isSystem: true, permIds: STAFF_PERMS,    forcePerms: false },
    { name: "READONLY", displayName: "Solo lectura",  isSystem: true, permIds: READONLY_PERMS, forcePerms: false },
  ] as const;

  let ownerRoleId = "";

  for (const r of roleDefs) {
    const role = await db.role.upsert({
      where: { jewelryId_name: { jewelryId, name: r.name } },
      create: { name: r.name, displayName: r.displayName, jewelryId, isSystem: r.isSystem },
      update: { isSystem: r.isSystem, deletedAt: null },
      select: { id: true },
    });

    if (r.name === "OWNER") ownerRoleId = role.id;

    if (r.forcePerms) {
      await db.rolePermission.deleteMany({ where: { roleId: role.id } });
      if (r.permIds.length) {
        await db.rolePermission.createMany({
          data: r.permIds.map((permissionId) => ({ roleId: role.id, permissionId })),
          skipDuplicates: true,
        });
      }
    } else {
      const existingCount = await db.rolePermission.count({ where: { roleId: role.id } });
      if (existingCount === 0 && r.permIds.length) {
        await db.rolePermission.createMany({
          data: r.permIds.map((permissionId) => ({ roleId: role.id, permissionId })),
          skipDuplicates: true,
        });
      }
    }
  }

  return { ownerRoleId };
}

/**
 * Creates all system defaults for a new tenant:
 *
 * Catálogos:
 *   DOCUMENT_TYPE (DNI, CUIT, CUIL)
 *   IVA_CONDITION (4 condiciones)
 *   PHONE_PREFIX  (10 países de referencia)
 *   COUNTRY       (10 países)
 *   PROVINCE      (24 provincias argentinas)
 *   CITY          (10 ciudades principales)
 *
 * Taxes:          IVA 21%, IVA 10.5%
 * PaymentMethods: Efectivo, Transferencia
 * ShippingCarriers: Retiro en sucursal, Envío estándar
 *
 * Currencies:
 *   ARS (base), USD (rate 1500), EUR (rate 1800)
 *
 * Metales:
 *   Oro     (AU, referenceValue 250.000 ARS/g) — AU24K, AU22K, AU18K, CH18K
 *   Plata   (AG, referenceValue   1.800 ARS/g) — AG100, AG950
 *   Platino (PT, referenceValue 230.000 ARS/g) — PT1000, PT950
 *   Cada variante genera MetalVariantValueHistory + MetalQuote en ARS.
 *
 * PriceLists:
 *   Lista Minorista — Valor Unificado (MARGIN_TOTAL 150%, isFavorite)
 *   Lista Mayorista — Valor Desglosado (METAL_HECHURA: metal 20% / hechura 50%)
 *   Lista Costo por Gramo (COST_PER_GRAM 120%)
 *
 * ArticleCategories: Anillos (+ 3 hijos) y Cadenas (+ 2 hijos)
 * ArticleAttributeDefs + assignments:
 *   Color de Oro → Anillos y Cadenas (inheritToChild: true)
 *   Color de Gemas → Anillos con piedras (inheritToChild: false)
 *
 * Idempotente: safe to call multiple times.
 */
export async function ensureSystemDefaults(
  db: Prisma.TransactionClient,
  jewelryId: string
): Promise<void> {
  const anyDb = db as any;

  // ── CatalogItems ────────────────────────────────────────────────────────
  type CatalogType = "IVA_CONDITION" | "DOCUMENT_TYPE" | "PHONE_PREFIX" | "COUNTRY" | "PROVINCE" | "CITY"
    | "PAYMENT_TERM" | "ARTICLE_BRAND" | "ARTICLE_MANUFACTURER" | "UNIT_OF_MEASURE" | "MULTIPLIER_BASE";

  const catalogDefaults: { type: CatalogType; label: string; isFavorite?: boolean }[] = [
    // Tipos de documento
    { type: "DOCUMENT_TYPE", label: "DNI",  isFavorite: true },
    { type: "DOCUMENT_TYPE", label: "CUIT" },
    { type: "DOCUMENT_TYPE", label: "CUIL" },

    // Condición IVA
    { type: "IVA_CONDITION", label: "Responsable Inscripto", isFavorite: true },
    { type: "IVA_CONDITION", label: "Monotributo"           },
    { type: "IVA_CONDITION", label: "Consumidor Final"      },
    { type: "IVA_CONDITION", label: "Exento"                },

    // Prefijos telefónicos (10 países de referencia)
    { type: "PHONE_PREFIX", label: "AR +54",  isFavorite: true }, // Argentina
    { type: "PHONE_PREFIX", label: "UY +598" }, // Uruguay
    { type: "PHONE_PREFIX", label: "CL +56"  }, // Chile
    { type: "PHONE_PREFIX", label: "BR +55"  }, // Brasil
    { type: "PHONE_PREFIX", label: "PY +595" }, // Paraguay
    { type: "PHONE_PREFIX", label: "BO +591" }, // Bolivia
    { type: "PHONE_PREFIX", label: "PE +51"  }, // Perú
    { type: "PHONE_PREFIX", label: "US +1"   }, // Estados Unidos
    { type: "PHONE_PREFIX", label: "ES +34"  }, // España
    { type: "PHONE_PREFIX", label: "IT +39"  }, // Italia

    // Países
    { type: "COUNTRY", label: "Argentina",      isFavorite: true },
    { type: "COUNTRY", label: "Uruguay"        },
    { type: "COUNTRY", label: "Chile"          },
    { type: "COUNTRY", label: "Brasil"         },
    { type: "COUNTRY", label: "Paraguay"       },
    { type: "COUNTRY", label: "Bolivia"        },
    { type: "COUNTRY", label: "Perú"           },
    { type: "COUNTRY", label: "Estados Unidos" },
    { type: "COUNTRY", label: "España"         },
    { type: "COUNTRY", label: "Italia"         },

    // Provincias argentinas
    { type: "PROVINCE", label: "Buenos Aires",         isFavorite: true },
    { type: "PROVINCE", label: "Catamarca"                     },
    { type: "PROVINCE", label: "Chaco"                         },
    { type: "PROVINCE", label: "Chubut"                        },
    { type: "PROVINCE", label: "Córdoba"                       },
    { type: "PROVINCE", label: "Corrientes"                    },
    { type: "PROVINCE", label: "Entre Ríos"                    },
    { type: "PROVINCE", label: "Formosa"                       },
    { type: "PROVINCE", label: "Jujuy"                         },
    { type: "PROVINCE", label: "La Pampa"                      },
    { type: "PROVINCE", label: "La Rioja"                      },
    { type: "PROVINCE", label: "Mendoza"                       },
    { type: "PROVINCE", label: "Misiones"                      },
    { type: "PROVINCE", label: "Neuquén"                       },
    { type: "PROVINCE", label: "Río Negro"                     },
    { type: "PROVINCE", label: "Salta"                         },
    { type: "PROVINCE", label: "San Juan"                      },
    { type: "PROVINCE", label: "San Luis"                      },
    { type: "PROVINCE", label: "Santa Cruz"                    },
    { type: "PROVINCE", label: "Santa Fe"                      },
    { type: "PROVINCE", label: "Santiago del Estero"           },
    { type: "PROVINCE", label: "Tierra del Fuego"              },
    { type: "PROVINCE", label: "Tucumán"                       },

    // Ciudades principales
    { type: "CITY", label: "Ciudad Autónoma de Buenos Aires", isFavorite: true },
    { type: "CITY", label: "La Plata"                        },
    { type: "CITY", label: "Mar del Plata"                   },
    { type: "CITY", label: "Córdoba"                         },
    { type: "CITY", label: "Rosario"                         },
    { type: "CITY", label: "Mendoza"                         },
    { type: "CITY", label: "San Miguel de Tucumán"           },
    { type: "CITY", label: "Salta"                           },
    { type: "CITY", label: "Neuquén"                         },
    { type: "CITY", label: "San Carlos de Bariloche"         },

    // Términos de pago
    { type: "PAYMENT_TERM", label: "Contado",  isFavorite: true },
    { type: "PAYMENT_TERM", label: "15 días"   },
    { type: "PAYMENT_TERM", label: "30 días"   },
    { type: "PAYMENT_TERM", label: "60 días"   },
    { type: "PAYMENT_TERM", label: "90 días"   },

    // Marcas de artículos
    { type: "ARTICLE_BRAND", label: "Genérica",  isFavorite: true },
    { type: "ARTICLE_BRAND", label: "Sin marca" },

    // Fabricantes
    { type: "ARTICLE_MANUFACTURER", label: "Fabricación propia", isFavorite: true },
    { type: "ARTICLE_MANUFACTURER", label: "Tercero"             },
    { type: "ARTICLE_MANUFACTURER", label: "Tuport - TPT"        },

    // Unidades de medida
    { type: "UNIT_OF_MEASURE", label: "Milimetros (mm)", isFavorite: true },
    { type: "UNIT_OF_MEASURE", label: "Centimetros (cm)" },
    { type: "UNIT_OF_MEASURE", label: "Metro (M)"        },

    // Bases del multiplicador de costo
    { type: "MULTIPLIER_BASE", label: "Gramos",  isFavorite: true },
    { type: "MULTIPLIER_BASE", label: "Kilates" },
  ];

  // Un solo batch insert en lugar de N upserts individuales — mucho más rápido dentro de TX
  await anyDb.catalogItem.createMany({
    data: catalogDefaults.map((item) => ({
      jewelryId,
      type:       item.type,
      label:      item.label,
      isFavorite: item.isFavorite ?? false,
      isSystem:   true,
      isActive:   true,
      sortOrder:  0,
    })),
    skipDuplicates: true,
  });

  // ── Taxes ────────────────────────────────────────────────────────────────
  const taxDefaults = [
    { name: "IVA 21%", code: "IVA21", rate: "21", applyOn: "TOTAL" as const, isFavorite: true },
  ];

  for (const t of taxDefaults) {
    const exists = await db.tax.findFirst({
      where: { jewelryId, code: t.code, deletedAt: null },
      select: { id: true },
    });
    if (!exists) {
      await db.tax.create({
        data: {
          jewelryId, name: t.name, code: t.code,
          taxType: "IVA", calculationType: "PERCENTAGE",
          rate: t.rate, applyOn: t.applyOn,
          isSystem: true, isActive: true,
          isFavorite: t.isFavorite ?? false,
        },
      });
    } else {
      await db.tax.update({ where: { id: exists.id }, data: { isSystem: true, isFavorite: t.isFavorite ?? false } });
    }
  }

  // ── PaymentMethods ───────────────────────────────────────────────────────
  const paymentDefaults: {
    name: string;
    code: string;
    type: "CASH" | "TRANSFER" | "CREDIT_CARD" | "DEBIT_CARD" | "QR" | "OTHER";
    isFavorite?: boolean;
    adjustmentType?: "NONE" | "PERCENTAGE" | "FIXED_AMOUNT";
    adjustmentValue?: string;
    installments?: { installments: number; interestRate: string; sortOrder: number }[];
  }[] = [
    { name: "Efectivo",           code: "CASH",     type: "CASH",        isFavorite: true  },
    { name: "Transferencia",      code: "TRANSFER", type: "TRANSFER"                       },
    {
      name: "Tarjeta de Crédito", code: "CREDIT",   type: "CREDIT_CARD",
      adjustmentType: "PERCENTAGE", adjustmentValue: "2",
      installments: [
        { installments: 3, interestRate: "10", sortOrder: 0 },
        { installments: 6, interestRate: "15", sortOrder: 1 },
      ],
    },
  ];

  for (const p of paymentDefaults) {
    let pmId: string;
    const exists = await db.paymentMethod.findFirst({
      where: { jewelryId, code: p.code, deletedAt: null },
      select: { id: true },
    });
    if (!exists) {
      const created = await db.paymentMethod.create({
        data: {
          jewelryId,
          name:            p.name,
          code:            p.code,
          type:            p.type,
          isFavorite:      p.isFavorite      ?? false,
          adjustmentType:  p.adjustmentType  ?? "NONE",
          adjustmentValue: p.adjustmentValue ?? null,
          isSystem:        true,
          isActive:        true,
        },
        select: { id: true },
      });
      pmId = created.id;
    } else {
      await db.paymentMethod.update({ where: { id: exists.id }, data: { isSystem: true } });
      pmId = exists.id;
    }

    // Cuotas: crear solo las que no existan aún
    for (const plan of p.installments ?? []) {
      const planExists = await anyDb.paymentInstallmentPlan.findFirst({
        where: { paymentMethodId: pmId, installments: plan.installments },
        select: { id: true },
      });
      if (!planExists) {
        await anyDb.paymentInstallmentPlan.create({
          data: {
            jewelryId,
            paymentMethodId: pmId,
            installments:    plan.installments,
            interestRate:    plan.interestRate,
            sortOrder:       plan.sortOrder,
            isActive:        true,
          },
        });
      }
    }
  }

  // ── ShippingCarriers ─────────────────────────────────────────────────────
  const shippingDefaults = [
    { name: "Retiro en sucursal", code: "PICKUP",   type: "PICKUP"   as const },
    { name: "Envío estándar",     code: "STANDARD", type: "DELIVERY" as const },
  ];

  for (const s of shippingDefaults) {
    const exists = await anyDb.shippingCarrier.findFirst({
      where: { jewelryId, code: s.code, deletedAt: null },
      select: { id: true },
    });
    if (!exists) {
      await anyDb.shippingCarrier.create({
        data: { jewelryId, name: s.name, code: s.code, type: s.type, isSystem: true, isActive: true },
      });
    } else {
      await anyDb.shippingCarrier.update({ where: { id: exists.id }, data: { isSystem: true } });
    }
  }

  // ── PriceLists ───────────────────────────────────────────────────────────
  // Identificadas por code único por tenant (@@unique([jewelryId, code])).
  // Los valores numéricos (márgenes) se cargan desde el inicio para que sean
  // visibles y educativos al abrir la pantalla por primera vez.
  const priceListDefaults: {
    code: string; name: string; description: string;
    mode: "MARGIN_TOTAL" | "METAL_HECHURA" | "COST_PER_GRAM";
    marginTotal?: string; marginMetal?: string; marginHechura?: string; costPerGram?: string;
    roundingTarget?: string; roundingMode?: string; roundingDirection?: string; roundingApplyOn?: string;
    isFavorite: boolean; sortOrder: number;
  }[] = [
    {
      code:             "MINORISTA",
      name:             "Lista Minorista — Valor Unificado",
      description:      "Precio de venta al público. Margen total del 85% sobre el costo base.",
      mode:             "MARGIN_TOTAL",
      marginTotal:      "85",
      roundingTarget:   "FINAL_PRICE",
      roundingMode:     "HUNDRED",
      roundingDirection: "NEAREST",
      roundingApplyOn:  "TOTAL",
      isFavorite:       true,
      sortOrder:        0,
    },
    {
      code:             "MAYORISTA",
      name:             "Lista Mayorista — Valor Desglosado",
      description:      "Precio mayorista. 10% sobre el metal y 50% sobre la hechura.",
      mode:             "METAL_HECHURA",
      marginMetal:      "10",
      marginHechura:    "50",
      roundingTarget:   "METAL",
      roundingMode:     "DECIMAL_1",
      roundingDirection: "NEAREST",
      roundingApplyOn:  "TOTAL",
      isFavorite:       false,
      sortOrder:        1,
    },
  ];

  for (const pl of priceListDefaults) {
    // upsert en @@unique([jewelryId, code]) — crea si no existe, restaura si fue borrado.
    // update: solo completa los márgenes si estaban vacíos (no sobreescribe valores del usuario).
    await db.priceList.upsert({
      where: { jewelryId_code: { jewelryId, code: pl.code } },
      create: {
        jewelryId,
        name:          pl.name,
        code:          pl.code,
        description:   pl.description,
        scope:         "GENERAL",
        mode:          pl.mode,
        isActive:      true,
        isFavorite:    pl.isFavorite,
        sortOrder:     pl.sortOrder,
        deletedAt:     null,
        marginTotal:      "marginTotal"   in pl ? pl.marginTotal   : null,
        marginMetal:      "marginMetal"   in pl ? pl.marginMetal   : null,
        marginHechura:    "marginHechura" in pl ? pl.marginHechura : null,
        costPerGram:      "costPerGram"   in pl ? pl.costPerGram   : null,
        roundingTarget:    (pl.roundingTarget   ?? "NONE")    as any,
        roundingMode:      (pl.roundingMode     ?? "NONE")    as any,
        roundingDirection: (pl.roundingDirection ?? "NEAREST") as any,
        roundingApplyOn:   (pl.roundingApplyOn  ?? "TOTAL")   as any,
      },
      update: {
        // Solo restaurar si fue borrado; no tocar valores que el usuario haya modificado
        deletedAt: null,
      },
    });
  }

  // ── Monedas (ARS base, USD, EUR) ─────────────────────────────────────────
  // Deben crearse ANTES que los metales (las variantes generan MetalQuote en ARS).
  const baseCurrencyId = await ensureCurrencies(anyDb, jewelryId);

  // ── Categorías de joyería + atributos ────────────────────────────────────
  const categoryIds = await ensureJewelryCategories(anyDb, jewelryId);
  await ensureJewelryAttributes(anyDb, jewelryId, categoryIds);

  // ── Metales + variantes ───────────────────────────────────────────────────
  await ensureMetalWithVariants(anyDb, jewelryId, baseCurrencyId, {
    name: "Oro", symbol: "AU", referenceValue: ORO_REF_VALUE, sortOrder: 1,
    variants: [
      { name: "Oro 24 Kilates",        sku: "AU24K", purity: 1.0,   saleFactor: 1.0  },
      { name: "Oro 22 Kilates",        sku: "AU22K", purity: 0.9,   saleFactor: 1.0  },
      { name: "Oro 18 Kilates",        sku: "AU18K", purity: 0.825, saleFactor: 1.0  },
      { name: "Chafalonia 18 Kilates", sku: "CH18K", purity: 0.7,   saleFactor: 0.95 },
    ],
  });

  await ensureMetalWithVariants(anyDb, jewelryId, baseCurrencyId, {
    name: "Plata", symbol: "AG", referenceValue: PLATA_REF_VALUE, sortOrder: 2,
    variants: [
      { name: "Plata - Granalla", sku: "AG100", purity: 1.0,  saleFactor: 1.0 },
      { name: "Plata 950",        sku: "AG950", purity: 0.95, saleFactor: 1.0 },
    ],
  });

  await ensureMetalWithVariants(anyDb, jewelryId, baseCurrencyId, {
    name: "Platino", symbol: "PT", referenceValue: PLATINO_REF_VALUE, sortOrder: 3,
    variants: [
      { name: "Platino",      sku: "PT1000", purity: 1.0, saleFactor: 1.0 },
      { name: "Platino 950",  sku: "PT950",  purity: 1.0, saleFactor: 1.2 },
    ],
  });

  // ── Entidades demo (solo si no hay ninguna) ────────────────────────────────
  await ensureDemoEntities(anyDb, jewelryId);
}

/**
 * Crea 2 clientes y 2 proveedores de demostración solo si el tenant aún no tiene entidades.
 * Los datos son ficticios y están claramente marcados con "[DEMO]".
 */
async function ensureDemoEntities(db: any, jewelryId: string): Promise<void> {
  const existing = await db.commercialEntity.count({ where: { jewelryId, deletedAt: null } });
  if (existing > 0) return;

  const demos = [
    { code: "CE-DEMO-001", displayName: "García, María", entityType: "PERSON", isClient: true, isSupplier: false, firstName: "María", lastName: "García", companyName: "", tradeName: "", email: "maria.garcia.demo@ejemplo.com", phone: "AR +54 11 5555-0001", documentType: "DNI", documentNumber: "00-000001-0", ivaCondition: "Consumidor Final", notes: "[DEMO] Cliente de muestra para explorar el sistema." },
    { code: "CE-DEMO-002", displayName: "Pérez Joyería", entityType: "COMPANY", isClient: true, isSupplier: false, firstName: "", lastName: "", companyName: "Joyería Pérez SA", tradeName: "Pérez Joyería", email: "contacto.demo@joyeriaperez.ejemplo.com", phone: "AR +54 11 5555-0002", documentType: "CUIT", documentNumber: "00-000002-0", ivaCondition: "Responsable Inscripto", notes: "[DEMO] Cliente empresa de muestra." },
    { code: "CE-DEMO-003", displayName: "Metales Demo", entityType: "COMPANY", isClient: false, isSupplier: true, firstName: "", lastName: "", companyName: "Distribuidora Metales Demo SRL", tradeName: "Metales Demo", email: "ventas.demo@metalesdemo.ejemplo.com", phone: "AR +54 11 5555-0003", documentType: "CUIT", documentNumber: "00-000003-0", ivaCondition: "Responsable Inscripto", notes: "[DEMO] Proveedor de metales de muestra." },
    { code: "CE-DEMO-004", displayName: "López, Roberto", entityType: "PERSON", isClient: false, isSupplier: true, firstName: "Roberto", lastName: "López", companyName: "", tradeName: "", email: "roberto.lopez.demo@ejemplo.com", phone: "AR +54 11 5555-0004", documentType: "CUIT", documentNumber: "00-000004-0", ivaCondition: "Monotributo", notes: "[DEMO] Proveedor persona física de muestra." },
  ];

  for (const d of demos) {
    const exists = await db.commercialEntity.findFirst({ where: { jewelryId, code: d.code }, select: { id: true } });
    if (!exists) {
      await db.commercialEntity.create({
        data: { ...d, jewelryId, balanceType: "UNIFIED", isActive: true, avatarUrl: "", sourceType: "MANUAL", paymentTerm: "" },
      });
    }
  }
}

/**
 * Initializes email branding fields in Jewelry using data from registration.
 * Only runs on first initialization (skipped if emailSenderName already set).
 *
 * Called exclusively from auth.controller.ts register() — NOT from seed.
 */
export async function ensureEmailBranding(
  db: Prisma.TransactionClient,
  jewelry: {
    id: string;
    name: string;
    phoneCountry: string;
    phoneNumber: string;
    street: string;
    number: string;
    city: string;
    province: string;
    country: string;
  },
  ownerEmail: string
): Promise<void> {
  // Skip if already initialized
  const existing = await db.jewelry.findUnique({
    where: { id: jewelry.id },
    select: { emailSenderName: true },
  });
  if (existing?.emailSenderName) return;

  const phone = [jewelry.phoneCountry, jewelry.phoneNumber].filter(Boolean).join(" ").trim();

  const addressParts = [
    jewelry.street && jewelry.number
      ? `${jewelry.street} ${jewelry.number}`
      : jewelry.street,
    jewelry.city,
    jewelry.province,
    jewelry.country,
  ].filter(Boolean);
  const addressLine = addressParts.join(", ");

  await db.jewelry.update({
    where: { id: jewelry.id },
    data: {
      emailEnabled:     true,
      emailSenderName:  jewelry.name,
      emailReplyTo:     ownerEmail,
      emailContact:     ownerEmail,
      emailPhone:       phone,
      emailAddressLine: addressLine,
      emailSignature:   jewelry.name,
      emailFooter:      addressLine ? `${jewelry.name} · ${addressLine}` : jewelry.name,
    },
  });
}
