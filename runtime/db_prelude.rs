use postgres::types::ToSql;

fn db_client() -> postgres::Client {
    let url = std::env::var("DATABASE_URL").expect("xeres: DATABASE_URL is not set");
    // TLS-capable connector: hosted Postgres (Supabase/Neon/RDS) requires SSL.
    // Honors sslmode in DATABASE_URL (e.g. ?sslmode=require / disable).
    let tls = postgres_native_tls::MakeTlsConnector::new(
        native_tls::TlsConnector::new().expect("xeres: TLS init failed"),
    );
    postgres::Client::connect(&url, tls).expect("xeres: database connection failed")
}
// R33 transactions: a `transaction { … }` block holds one shared connection in
// this thread-local for its duration (BEGIN..COMMIT/ROLLBACK). While it's set,
// db_exec/db_query run on it (so they're part of the transaction) and flip the
// `failed` flag on any error, so tx_end rolls back. Outside a transaction each
// call opens its own connection, as before. Thread-per-connection + Connection:
// close means the slot never crosses requests.
thread_local! { static TX: std::cell::RefCell<Option<(postgres::Client, bool)>> = std::cell::RefCell::new(None); }
fn tx_begin() {
    let mut c = db_client();
    let failed = c.batch_execute("BEGIN").is_err();
    TX.with(|t| *t.borrow_mut() = Some((c, failed)));
}
fn tx_end() {
    TX.with(|t| {
        if let Some((mut c, failed)) = t.borrow_mut().take() {
            let _ = c.batch_execute(if failed { "ROLLBACK" } else { "COMMIT" });
        }
    });
}
fn db_exec(sql: &str, params: &[&(dyn ToSql + Sync)]) -> i64 {
    TX.with(|t| {
        let mut b = t.borrow_mut();
        if let Some((c, failed)) = b.as_mut() {
            match c.execute(sql, params) {
                Ok(n) => n as i64,
                Err(_) => { *failed = true; 0 }
            }
        } else {
            drop(b);
            db_client().execute(sql, params).map(|n| n as i64).unwrap_or(0)
        }
    })
}
fn db_query(sql: &str, params: &[&(dyn ToSql + Sync)]) -> Vec<postgres::Row> {
    TX.with(|t| {
        let mut b = t.borrow_mut();
        if let Some((c, failed)) = b.as_mut() {
            match c.query(sql, params) {
                Ok(r) => r,
                Err(_) => { *failed = true; Vec::new() }
            }
        } else {
            drop(b);
            db_client().query(sql, params).expect("xeres: database query failed")
        }
    })
}
