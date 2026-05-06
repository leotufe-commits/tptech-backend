// Ajuste de cupón — capa pura sin acceso a DB.
//
// Se aplica DESPUÉS del canal de venta y ANTES de la forma de pago,
// siguiendo el orden: lista → canal → cupón → pago → impuestos → redondeo.

export type CouponInput = {
  id:            string;
  code:          string;
  name:          string;
  discountType:  "PERCENTAGE" | "FIXED_AMOUNT";
  discountValue: number;
};

export type CouponAdjustmentResult = {
  baseAmount:     number;       // precio antes del cupón
  discountAmount: number;       // monto descontado (siempre >= 0)
  finalAmount:    number;       // baseAmount - discountAmount (nunca < 0)
  couponId:       string;
  couponCode:     string;
  couponName:     string;
  discountType:   "PERCENTAGE" | "FIXED_AMOUNT";
  discountValue:  number;
  applied:        boolean;
  reason?:        string;       // si applied=false, motivo legible
};

export function applyCouponAdjustment(
  baseAmount: number | null,
  coupon:     CouponInput | null,
): CouponAdjustmentResult {
  const base = Number.isFinite(baseAmount as number) && baseAmount != null ? (baseAmount as number) : 0;

  if (!coupon) {
    return {
      baseAmount:     base,
      discountAmount: 0,
      finalAmount:    base,
      couponId:       "",
      couponCode:     "",
      couponName:     "",
      discountType:   "PERCENTAGE",
      discountValue:  0,
      applied:        false,
    };
  }

  const value = Number.isFinite(coupon.discountValue) ? coupon.discountValue : 0;

  let rawDiscount: number;
  if (coupon.discountType === "PERCENTAGE") {
    rawDiscount = round2(base * (Math.max(0, Math.min(100, value)) / 100));
  } else {
    rawDiscount = round2(Math.max(0, value));
  }

  // El descuento no puede superar el precio base (precio nunca negativo)
  const discountAmount = Math.min(rawDiscount, base);
  const finalAmount    = round2(base - discountAmount);

  return {
    baseAmount:   base,
    discountAmount,
    finalAmount,
    couponId:    coupon.id,
    couponCode:  coupon.code,
    couponName:  coupon.name,
    discountType: coupon.discountType,
    discountValue: coupon.discountValue,
    applied:     true,
  };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
