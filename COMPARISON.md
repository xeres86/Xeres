# Xeres vs the JS/TS frameworks

The same feature in each stack:

> Fetch a user by id **on the server**, render their **name** in the browser, and
> make it **impossible to leak `passwordHash`** to the client.

The interesting axis is **where the server/client boundary lives** and **who
enforces it** — the compiler, or you.

---

## Xeres — one file, boundary enforced by the type system

```xeres
model User {
  id: String
  name: String
  secret password_hash: String      // opts OUT of the wire
}

server fn get_user(id: String) -> User {
  return db_find(id)                 // the db handle physically cannot cross to ui
}

ui screen Profile(user: User) {
  view {
    column {
      heading user.name
      // text user.password_hash     // ← compile error R3: secret in the browser
    }
  }
}
```

- **Files:** 1. **Runtime deps in the browser:** 0.
- The compiler generates the RPC, strips `password_hash` from the wire, and
  *rejects a leak at build time*. The boundary is a **type**, not a convention.

---

## Next.js (App Router, RSC + Server Action)

```tsx
// app/profile/[id]/page.tsx — Server Component
import { db } from "@/lib/db";          // ⚠ importing this in a "use client" file leaks it
export default async function Page({ params }: { params: { id: string } }) {
  const user = await db.user.findUnique({ where: { id: params.id } });
  // ⚠ nothing stops you passing user.passwordHash down
  return <ProfileView name={user!.name} />;
}

// app/profile/[id]/ProfileView.tsx
"use client";
export function ProfileView({ name }: { name: string }) {
  return <div><h2>{name}</h2></div>;
}
```

- **Files:** 2+ (`page`, client component, `lib/db`). **Deps:** `next`, `react`,
  `react-dom`, an ORM, …
- Boundary is the `"use client"` / `"use server"` **convention**. Secret-stripping
  is *your discipline* — forget a `select` and the hash ships.

---

## React (Vite SPA) + Express API — you write both halves

```ts
// server/index.ts (Express) — a separate process you build and deploy yourself
app.get("/api/user/:id", async (req, res) => {
  const u = await db.user.findUnique({ where: { id: req.params.id } });
  res.json({ id: u.id, name: u.name }); // must hand-pick fields to avoid leaking
});
```

```tsx
// src/Profile.tsx
import { useEffect, useState } from "react";
export function Profile({ id }: { id: string }) {
  const [user, setUser] = useState<{ name: string } | null>(null);
  useEffect(() => {
    fetch(`/api/user/${id}`).then(r => r.json()).then(setUser);
  }, [id]);
  if (!user) return <p>Loading…</p>;
  return <div><h2>{user.name}</h2></div>;
}
```

- **Files:** 2 codebases (client + server), CORS, a fetch layer, manual loading
  state, and **types are not shared across the wire** (the `{name}` shape is
  duplicated by hand). Secret safety is a manual `res.json({...})`.

---

## Angular (component + service + HttpClient) + separate backend

```ts
// user.service.ts
@Injectable({ providedIn: "root" })
export class UserService {
  constructor(private http: HttpClient) {}
  getUser(id: string) { return this.http.get<{ name: string }>(`/api/user/${id}`); }
}
```

```ts
// profile.component.ts
@Component({
  selector: "app-profile",
  template: `<h2 *ngIf="user">{{ user.name }}</h2>`,
})
export class ProfileComponent implements OnInit {
  @Input() id!: string;
  user?: { name: string };
  constructor(private users: UserService) {}
  ngOnInit() { this.users.getUser(this.id).subscribe(u => (this.user = u)); }
}
```

- **Files:** service + component + module + a separate backend. **Deps:** the full
  Angular framework + RxJS. Boundary and secret-stripping again live in the
  hand-written backend.

---

## SvelteKit (server `load` + page)

```ts
// +page.server.ts
import { db } from "$lib/db";
export async function load({ params }) {
  const u = await db.user.findUnique({ where: { id: params.id } });
  return { name: u.name };               // return only what's safe — your call
}
```

```svelte
<!-- +page.svelte -->
<script>export let data;</script>
<h2>{data.name}</h2>
```

- The closest in spirit to Xeres: the `+page.server.ts` boundary is real and
  ergonomic. But secret-stripping is still *"return only what's safe — your call,"*
  not a compiler guarantee, and the browser still ships the Svelte runtime.

---

## At a glance

| | Files | Browser runtime deps | Boundary defined by | Types shared across wire | Secret leak is… |
|---|---|---|---|---|---|
| **Xeres** | 1 | 0 | the **type system** | yes (same `model`) | a **compile error** |
| Next.js RSC | 2+ | react/react-dom | `"use client/server"` convention | partial | a code-review item |
| React + Express | 2 codebases | react/react-dom | hand-written API | no (duplicated) | a code-review item |
| Angular + API | 4+ | angular + rxjs | hand-written API | no (duplicated) | a code-review item |
| SvelteKit | 2 | svelte runtime | `+page.server.ts` | yes | a code-review item |

**The takeaway:** everyone else makes the server/client boundary something you
*maintain by discipline*. Xeres makes it something the *compiler enforces* — a
secret reaching the browser isn't a bug you hunt for in review, it's a program
that doesn't compile.
