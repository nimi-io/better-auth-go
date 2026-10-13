// Databases for the shared-database tests. SQLite always runs; PostgreSQL and MySQL use
// the docker-compose servers (skipped when unreachable unless BA_TEST_REQUIRE_DBS=1).
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const PG = process.env.BA_TEST_POSTGRES_URL || "postgres://better_auth:better_auth@localhost:5433/better_auth?sslmode=disable";
const MONGO = process.env.BA_E2E_MONGO_URL || "mongodb://localhost:27018/?directConnection=true";
const MYSQL = process.env.BA_E2E_MYSQL_URL || "mysql://root:root@localhost:3307/";

const name = () => "ba_e2e_" + Math.random().toString(36).slice(2, 12);

async function unavailable(what, err) {
  if (process.env.BA_TEST_REQUIRE_DBS === "1") throw err;
  console.warn(`[shared-db] ${what} unavailable, skipping: ${err.message}`);
  return null;
}

export function databases() {
  return [
    {
      name: "sqlite",
      async create() {
        const dir = mkdtempSync(path.join(tmpdir(), "ba-e2e-"));
        return { url: `sqlite:${path.join(dir, "shared.db")}`, drop: async () => rmSync(dir, { recursive: true, force: true }) };
      },
    },
    {
      name: "postgres",
      async create() {
        let pg;
        try { pg = (await import("pg")).default; } catch (e) { return unavailable("pg module", e); }
        const admin = new pg.Client({ connectionString: PG });
        try { await admin.connect(); } catch (e) { return unavailable("PostgreSQL", e); }
        const db = name();
        await admin.query(`CREATE DATABASE ${db}`);
        const u = new URL(PG);
        u.pathname = `/${db}`;
        u.search = "";
        return {
          url: u.toString(),
          drop: async () => { await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`); await admin.end(); },
        };
      },
    },
    {
      name: "mysql",
      async create() {
        let mysql;
        try { mysql = await import("mysql2/promise"); } catch (e) { return unavailable("mysql2 module", e); }
        let admin;
        try { admin = await mysql.createConnection(MYSQL); } catch (e) { return unavailable("MySQL", e); }
        const db = name();
        await admin.query(`CREATE DATABASE ${db}`);
        const u = new URL(MYSQL);
        u.pathname = `/${db}`;
        return { url: u.toString(), drop: async () => { await admin.query(`DROP DATABASE IF EXISTS ${db}`); await admin.end(); } };
      },
    },
    {
      name: "mongodb",
      migrations: false,
      async create() {
        let MongoClient;
        try { ({ MongoClient } = await import("mongodb")); } catch (e) { return unavailable("mongodb module", e); }
        const admin = new MongoClient(MONGO, { serverSelectionTimeoutMS: 3000 });
        try { await admin.connect(); } catch (e) { return unavailable("MongoDB", e); }
        const db = name();
        const u = new URL(MONGO);
        u.pathname = `/${db}`;
        return { url: u.toString(), drop: async () => { await admin.db(db).dropDatabase(); await admin.close(); } };
      },
    },
  ];
}
