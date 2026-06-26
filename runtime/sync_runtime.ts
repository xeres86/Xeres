// ---- xeres local-first sync runtime (field-level LWW) ----
// A synced collection stores each row as a map of field -> Cell: the field's
// value plus its own Lamport stamp + site id. Concurrent edits to *different*
// fields of the same row therefore both survive. A delete is a row tombstone with
// its own stamp; a row is visible unless its tombstone dominates every field
// stamp. Stamps form a total order (higher Lamport wins, ties broken by the
// stable random site id), so every replica converges. The wire shape + merge
// mirror the server (src/serve.rs and the generated sync_dispatch).
type Stamp = { lamport: number; site: string };
type Cell = { value: any; lamport: number; site: string };
type CellOp =
  | { kind: "set"; id: string; field: string; value: any; lamport: number; site: string }
  | { kind: "del"; id: string; lamport: number; site: string };

// Total order on stamps: higher Lamport wins; equal Lamports break by the
// lexicographically-greater site id. True iff `a` strictly dominates `b`.
function stampGt(a: Stamp, b: Stamp): boolean {
  return a.lamport > b.lamport || (a.lamport === b.lamport && a.site > b.site);
}

export interface LocalStore<T> {
  load(): { cells: Map<string, Map<string, Cell>>; tombs: Map<string, Stamp>; lamport: number; site: string };
  persist(cells: Map<string, Map<string, Cell>>, tombs: Map<string, Stamp>, lamport: number, site: string): void;
}

// Default adapter: in-memory mirror, snapshotted to localStorage. Replace with a
// SQLite-backed adapter (sql.js / cr-sqlite) without changing SyncedCollection.
class MemoryStore<T> implements LocalStore<T> {
  constructor(private key: string) {}
  load() {
    try {
      const raw = typeof localStorage !== "undefined" ? localStorage.getItem(this.key) : null;
      if (raw) {
        const o = JSON.parse(raw);
        const cells = new Map<string, Map<string, Cell>>();
        for (const [id, fobj] of Object.entries(o.cells ?? {})) {
          cells.set(id, new Map(Object.entries(fobj as Record<string, Cell>)));
        }
        const tombs = new Map(Object.entries(o.tombs ?? {})) as Map<string, Stamp>;
        return { cells, tombs, lamport: o.lamport ?? 0, site: o.site ?? "" };
      }
    } catch { /* fall through to empty */ }
    return { cells: new Map<string, Map<string, Cell>>(), tombs: new Map<string, Stamp>(), lamport: 0, site: "" };
  }
  persist(cells: Map<string, Map<string, Cell>>, tombs: Map<string, Stamp>, lamport: number, site: string) {
    if (typeof localStorage === "undefined") return;
    const cellsObj: Record<string, Record<string, Cell>> = {};
    for (const [id, fmap] of cells) cellsObj[id] = Object.fromEntries(fmap);
    localStorage.setItem(this.key, JSON.stringify({
      cells: cellsObj,
      tombs: Object.fromEntries(tombs),
      lamport,
      site,
    }));
  }
}

export class SyncedCollection<T extends { id: string }> {
  private cells = new Map<string, Map<string, Cell>>(); // id -> field -> cell
  private tombs = new Map<string, Stamp>();              // id -> delete stamp
  private rows = new Map<string, T>();                   // derived: live rows only
  private pending: CellOp[] = [];
  private lamport = 0;
  private site: string;
  private subs = new Set<(rows: T[]) => void>();

  constructor(private name: string, private store: LocalStore<T> = new MemoryStore<T>("xeres:" + name + ":v2")) {
    const snap = store.load();
    this.cells = snap.cells; this.tombs = snap.tombs; this.lamport = snap.lamport;
    // A stable, random site id breaks equal-Lamport ties deterministically.
    this.site = snap.site || Math.random().toString(36).slice(2) + Date.now().toString(36);
    for (const id of new Set([...this.cells.keys(), ...this.tombs.keys()])) this.materialize(id);
    if (typeof addEventListener !== "undefined") addEventListener("online", () => { void this.sync(); });
    if (typeof setInterval !== "undefined") setInterval(() => { void this.sync(); }, 2000); // trawler
  }

  all(): T[] { return [...this.rows.values()]; }
  get(id: string): T | undefined { return this.rows.get(id); }

  subscribe(fn: (rows: T[]) => void): () => void {
    this.subs.add(fn); fn(this.all());
    return () => { this.subs.delete(fn); };
  }

  // Add or update a row. Only the fields whose value actually changed get a fresh
  // stamp, so a concurrent edit to a *different* field of the same row is not
  // clobbered. A row that isn't currently live (new id, or one re-added after a
  // delete) re-stamps every field so it cleanly revives past the tombstone.
  add(row: T): void {
    const id = row.id;
    const reviving = !this.rows.has(id);
    const cur = this.cells.get(id);
    const changed: string[] = [];
    for (const k of Object.keys(row)) {
      const prev = cur ? cur.get(k) : undefined;
      if (reviving || !prev || JSON.stringify(prev.value) !== JSON.stringify((row as any)[k])) changed.push(k);
    }
    if (changed.length === 0) return;
    this.lamport++;
    let dirty = false;
    for (const field of changed) {
      const op: CellOp = { kind: "set", id, field, value: (row as any)[field], lamport: this.lamport, site: this.site };
      dirty = this.applyCell(op) || dirty;
      this.pending.push(op);
    }
    if (dirty) this.commit();
    void this.sync();
  }

  remove(id: string): void {
    this.lamport++;
    const op: CellOp = { kind: "del", id, lamport: this.lamport, site: this.site };
    const dirty = this.applyCell(op);
    this.pending.push(op);
    if (dirty) this.commit();
    void this.sync();
  }

  // Merge one cell op into the field/tomb maps (the same field-level LWW the
  // server runs). Returns whether the visible row set may have changed.
  private applyCell(op: CellOp): boolean {
    if (op.lamport > this.lamport) this.lamport = op.lamport;
    if (op.kind === "set") {
      let fields = this.cells.get(op.id);
      const prev = fields ? fields.get(op.field) : undefined;
      if (prev && !stampGt(op, prev)) return false;
      if (!fields) { fields = new Map<string, Cell>(); this.cells.set(op.id, fields); }
      fields.set(op.field, { value: op.value, lamport: op.lamport, site: op.site });
    } else {
      const prev = this.tombs.get(op.id);
      if (prev && !stampGt(op, prev)) return false;
      this.tombs.set(op.id, { lamport: op.lamport, site: op.site });
    }
    return this.materialize(op.id);
  }

  // Recompute the live row for `id` from its cells + tombstone. A tombstone hides
  // the row unless some field stamp strictly dominates it. Returns whether the
  // visible set changed.
  private materialize(id: string): boolean {
    const fields = this.cells.get(id);
    const tomb = this.tombs.get(id);
    const alive = !!fields && fields.size > 0 && (!tomb || [...fields.values()].some((c) => stampGt(c, tomb)));
    if (alive) {
      const obj: any = {};
      for (const [f, c] of fields!) obj[f] = c.value;
      this.rows.set(id, obj as T);
      return true;
    }
    if (this.rows.has(id)) { this.rows.delete(id); return true; }
    return false;
  }

  private commit(): void {
    this.store.persist(this.cells, this.tombs, this.lamport, this.site);
    const rows = this.all();
    this.subs.forEach((f) => f(rows));
  }

  // Network trawler step: flush the offline oplog, pull authoritative changes,
  // merge. Fully offline-safe — any failure leaves the queue intact for retry.
  async sync(): Promise<void> {
    if (typeof navigator !== "undefined" && navigator.onLine === false) return;
    let res: Response;
    try {
      res = await fetch(`/__xeres/sync/${this.name}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ since: this.lamport, ops: this.pending }),
      });
    } catch { return; }
    if (!res.ok) return;
    const remote = (await res.json()) as { lamport: number; ops: CellOp[] };
    let changed = false;
    for (const op of remote.ops ?? []) changed = this.applyCell(op) || changed;
    this.pending = [];
    this.lamport = Math.max(this.lamport, remote.lamport ?? this.lamport);
    if (changed) this.commit();
  }
}
