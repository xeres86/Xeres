# Xeres cookbook

Short, copy-pasteable recipes. Every snippet here compiles. Drop a `ui screen`
into your `app.xrs` (the first prop-less screen auto-mounts); put `model`s and
`server fn`s at the top level.

- [UI basics](#ui-basics)
- [Lists & local-first data](#lists--local-first-data)
- [Talking to the server](#talking-to-the-server)
- [The secret boundary](#the-secret-boundary)
- [Types: Optional & List](#types-optional--list)
- [Database (PostgreSQL)](#database-postgresql)

---

## UI basics

### A counter
```xeres
ui screen App {
  state count: Int = 0
  view {
    column {
      heading "Counter"
      text count
      row {
        button "-" -> { count = count - 1 }
        button "+" -> { count = count + 1 }
      }
    }
  }
}
```

### Text input + live output
`bind` makes a two-way binding to a `state` cell.
```xeres
ui screen App {
  state name: String = ""
  view {
    column {
      input "Your name" bind name
      text "Hello, " + name
    }
  }
}
```

### Show / hide (conditional rendering)
```xeres
ui screen App {
  state open: Bool = false
  view {
    column {
      button "toggle" -> { open = !open }
      if open {
        text "now you see me"
      } else {
        text "(hidden)"
      }
    }
  }
}
```

### A password field
`password` is a masked input; otherwise it behaves like `input`.
```xeres
ui screen App {
  state pw: String = ""
  view {
    column {
      password "Password" bind pw
    }
  }
}
```

---

## Lists & local-first data

### A todo list (offline-first, syncs automatically)
A `synced state` is a local-first collection: it persists on-device and syncs in
the background. `uid()` generates a unique id.
```xeres
model Task { id: String  title: String }
synced state tasks: Collection<Task>

ui screen App {
  state draft: String = ""
  view {
    column {
      heading "Todo"
      row {
        input "New task" bind draft
        button "add" -> { tasks.add(Task { id: uid(), title: draft }) draft = "" }
      }
      for task in tasks {
        row {
          text task.title
          button "x" -> { tasks.remove(task.id) }
        }
      }
    }
  }
}
```

---

## Talking to the server

### Call a server function
A `ui` call to a `server fn` is a typed RPC — the compiler generates it; you mark
the network hop with `await`. The function body never ships to the browser.
```xeres
server fn add(a: Int, b: Int) -> Int {
  return a + b
}

ui screen App {
  state sum: Int = 0
  view {
    column {
      button "2 + 3 on the server" -> {
        let s = await add(2, 3)
        sum = s
      }
      text sum
    }
  }
}
```

### Handle a failing call
`try`/`catch` covers any RPC failure (network down, server error) in one place.
```xeres
server fn greet(name: String) -> String {
  return name
}

ui screen App {
  state msg: String = ""
  view {
    column {
      button "greet" -> {
        try {
          let who = await greet("world")
          msg = "Hi, " + who
        } catch {
          msg = "request failed"
        }
      }
      text msg
    }
  }
}
```

### A loading indicator
Flip a `Bool` around the `await`, then render on it.
```xeres
server fn slow(n: Int) -> Int { return n }

ui screen App {
  state loading: Bool = false
  state result: Int = 0
  view {
    column {
      button "load" -> {
        loading = true
        let r = await slow(42)
        result = r
        loading = false
      }
      if loading {
        text "loading..."
      } else {
        text result
      }
    }
  }
}
```

---

## The secret boundary

A `secret` model field cannot be read in browser code and is stripped from every
response. It may only be touched server-side; release a *derived* result (never
the secret itself) through the single audited keyword `declassify`.
```xeres
model User {
  id: String
  username: String
  secret password_hash: String   // never crosses to the browser
}

server fn verify(user: User, attempt: String) -> Bool {
  // the comparison happens here, server-side; only the boolean escapes
  return declassify(user.password_hash == attempt)
}
```

---

## Types: Optional & List

### Optional fields + a default
A field typed `Optional<T>` may be omitted (defaults to `none`); a bare `T` also
fits. `.or(default)` unwraps it.
```xeres
model Profile {
  id: String
  name: String
  nickname: Optional<String>
}

ui fn display_name(p: Profile) -> String {
  return p.nickname.or(p.name)   // nickname if present, else name
}
```

### Returning a list
```xeres
server fn tags() -> List<String> {
  return ["alpha", "beta", "gamma"]
}
```

---

## Database (PostgreSQL)

`db` is a server-only capability — the connection and credentials can never reach
the browser. Set `DATABASE_URL` in `.env`. (`db` apps need the database-enabled
compiler build.)

### Read one row → a model
`query_one` maps the row's columns onto the function's return model.
```xeres
model User { id: String  username: String  secret password_hash: String }

server fn get_user(name: String) -> User {
  return db.query_one("select id, username, password_hash from users where username = $1", name)
}
```

### Read many rows → a list
```xeres
server fn recent_users() -> List<User> {
  return db.query("select id, username, password_hash from users order by id desc")
}
```

### Insert / update / delete
`exec` returns the number of rows affected.
```xeres
server fn add_user(id: String, username: String, hash: String) -> Int {
  return db.exec("insert into users (id, username, password_hash) values ($1, $2, $3)", id, username, hash)
}
```

---

See [`examples/`](../examples) for full apps (counter, todo, login, notes), and
the [README](../README.md) for the rule set and how it all compiles.
