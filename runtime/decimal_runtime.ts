const __dec = {
  _p(x: any): [bigint, number] {
    let s = String(x).trim();
    const neg = s.charAt(0) === "-";
    if (neg || s.charAt(0) === "+") s = s.slice(1);
    const dot = s.indexOf(".");
    const frac = dot < 0 ? "" : s.slice(dot + 1);
    const digits = (dot < 0 ? s : s.slice(0, dot) + frac) || "0";
    let v = BigInt(digits);
    if (neg) v = -v;
    return [v, frac.length];
  },
  _fmt(v: bigint, scale: number): string {
    const neg = v < 0n;
    let s = (neg ? -v : v).toString();
    let body: string;
    if (scale === 0) {
      body = s;
    } else {
      if (s.length <= scale) s = s.padStart(scale + 1, "0");
      const cut = s.length - scale;
      body = s.slice(0, cut) + "." + s.slice(cut);
    }
    return neg ? "-" + body : body;
  },
  _bin(a: any, b: any): [bigint, bigint, number] {
    const [av, asc] = this._p(a);
    const [bv, bsc] = this._p(b);
    const sc = asc > bsc ? asc : bsc;
    return [av * 10n ** BigInt(sc - asc), bv * 10n ** BigInt(sc - bsc), sc];
  },
  add(a: any, b: any): string { const [x, y, sc] = this._bin(a, b); return this._fmt(x + y, sc); },
  sub(a: any, b: any): string { const [x, y, sc] = this._bin(a, b); return this._fmt(x - y, sc); },
  mul(a: any, b: any): string { const [av, asc] = this._p(a); const [bv, bsc] = this._p(b); return this._fmt(av * bv, asc + bsc); },
  lt(a: any, b: any): boolean { const [x, y] = this._bin(a, b); return x < y; },
  gt(a: any, b: any): boolean { const [x, y] = this._bin(a, b); return x > y; },
  le(a: any, b: any): boolean { const [x, y] = this._bin(a, b); return x <= y; },
  ge(a: any, b: any): boolean { const [x, y] = this._bin(a, b); return x >= y; },
};
