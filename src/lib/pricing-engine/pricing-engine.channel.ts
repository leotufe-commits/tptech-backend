// Ajuste de canal de venta — capa pura sin acceso a DB.
//
// Se aplica DESPUÉS de resolveFinalSalePrice y ANTES de resolveCheckoutPrice,
// siguiendo el orden: lista → canal → pago → impuestos → redondeo.
//
// Ejemplo de uso:
//   const r = await resolveFinalSalePrice(...);
//   const ch = applySalesChannelAdjustment(r.unitPrice?.toNumber() ?? null, channel);
//   const checkout = resolveCheckoutPrice({ unitPrice: ch.finalAmount, ... });

export type ChannelAdjustmentInput = {
  id:             string;
  name:           string;
  adjustmentType: "PERCENTAGE" | "FIXED";
  adjustmentValue: number;
};

export type ChannelAdjustmentResult = {
  baseAmount:    number;        // unitPrice antes del canal
  channelAmount: number;        // delta aplicado (puede ser negativo)
  finalAmount:   number;        // baseAmount + channelAmount
  channelName:   string;
  channelId:     string;
};

export function applySalesChannelAdjustment(
  baseAmount: number | null,
  channel:    ChannelAdjustmentInput | null,
): ChannelAdjustmentResult {
  const base = Number.isFinite(baseAmount as number) ? (baseAmount as number) : 0;

  if (!channel) {
    return { baseAmount: base, channelAmount: 0, finalAmount: base, channelName: "", channelId: "" };
  }

  const value = Number.isFinite(channel.adjustmentValue) ? channel.adjustmentValue : 0;
  const channelAmount =
    channel.adjustmentType === "PERCENTAGE"
      ? round2(base * (value / 100))
      : round2(value);

  return {
    baseAmount:    base,
    channelAmount,
    finalAmount:   round2(base + channelAmount),
    channelName:   channel.name,
    channelId:     channel.id,
  };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
