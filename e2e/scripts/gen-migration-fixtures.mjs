// Generates the schema-migration fixtures verified by adapter/sqladapter/migration (Go) using
// the real getMigrations of better-auth@1.7.7 against fresh SQLite, PostgreSQL and MySQL
// databases.
//
//   node scripts/gen-migration-fixtures.mjs              # regenerate testdata/fixtures.json
//   node scripts/gen-migration-fixtures.mjs crosscheck   # read jobs (JSON) on stdin, used by
//                                                        # the Go cross-check tests
//
// The configurations live in adapter/sqladapter/migration/testdata/configs.json and are shared
// with the Go tests. PostgreSQL and MySQL use the docker-compose servers
// (BA_TEST_POSTGRES_URL / BA_E2E_MYSQL_URL override the defaults).
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import pg from "pg";
import mysql from "mysql2/promise";
import { MssqlAdapter, MssqlQueryCompiler, PostgresDialect } from "kysely";
import { getMigrations } from "better-auth/db/migration";

const PG = process.env.BA_TEST_POSTGRES_URL || "postgres://better_auth:better_auth@localhost:5433/better_auth?sslmode=disable";
const MYSQL = process.env.BA_E2E_MYSQL_URL || "mysql://root:root@localhost:3307/";
const testdata = new URL("../../adapter/sqladapter/migration/testdata/", import.meta.url);
const { configs } = JSON.parse(readFileSync(new URL("configs.json", testdata), "utf8"));
const DIALECTS = ["sqlite", "postgres", "mysql"];

// ---- configuration --------------------------------------------------------------------

function field(spec) {
  const out = { ...spec };
  if (spec.defaultValue && typeof spec.defaultValue === "object" && "$fn" in spec.defaultValue) {
    out.defaultValue = spec.defaultValue.$fn === "date" ? () => new Date() : () => Date.now();
  }
  return out;
}

function fields(map) {
  if (!map) return map;
  return Object.fromEntries(Object.entries(map).map(([k, v]) => [k, field(v)]));
}

function toOptions(spec) {
  const out = {};
  for (const key of ["user", "session", "account", "verification"]) {
    if (!spec[key]) continue;
    out[key] = { ...spec[key], additionalFields: fields(spec[key].additionalFields) };
  }
  if (spec.rateLimit) out.rateLimit = { enabled: true, ...spec.rateLimit };
  if (spec.advanced) out.advanced = spec.advanced;
  if (spec.plugins) {
    out.plugins = spec.plugins.map((p) => ({
      id: p.id,
      schema: Object.fromEntries(
        Object.entries(p.schema).map(([k, t]) => [k, { ...t, fields: fields(t.fields) }]),
      ),
    }));
  }
  return out;
}

// ---- databases ------------------------------------------------------------------------

const randomName = () => "ba_mig_" + Math.random().toString(36).slice(2, 12);

async function createDatabase(dialect) {
  if (dialect === "sqlite") {
    const dir = mkdtempSync(path.join(tmpdir(), "ba-mig-"));
    return { url: path.join(dir, "test.db"), drop: async () => rmSync(dir, { recursive: true, force: true }) };
  }
  if (dialect === "postgres") {
    const admin = new pg.Client({ connectionString: PG });
    await admin.connect();
    const name = randomName();
    await admin.query(`CREATE DATABASE ${name}`);
    const u = new URL(PG);
    u.pathname = `/${name}`;
    return {
      url: u.toString(),
      drop: async () => {
        await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
        await admin.end();
      },
    };
  }
  const admin = await mysql.createConnection(MYSQL);
  const name = randomName();
  await admin.query(`CREATE DATABASE ${name}`);
  const u = new URL(MYSQL);
  u.pathname = `/${name}`;
  return {
    url: u.toString(),
    drop: async () => {
      await admin.query(`DROP DATABASE IF EXISTS ${name}`);
      await admin.end();
    },
  };
}

// fakeMssql is a SQL Server dialect over a driver that answers every query with no rows:
// there is no SQL Server test database, but Kysely compiles the DDL without one, so the
// fixtures cover the SQL Server type mapping for fresh databases.
function fakeMssql() {
  const connection = {
    async executeQuery() {
      return { rows: [] };
    },
    async *streamQuery() {
      throw new Error("not supported");
    },
  };
  return {
    createAdapter: () => new MssqlAdapter(),
    createDriver: () => ({
      async init() {},
      async acquireConnection() {
        return connection;
      },
      async beginTransaction() {},
      async commitTransaction() {},
      async rollbackTransaction() {},
      async releaseConnection() {},
      async destroy() {},
    }),
    createIntrospector: () => ({
      async getSchemas() {
        return [];
      },
      async getTables() {
        return [];
      },
      async getMetadata() {
        return { tables: [] };
      },
    }),
    createQueryCompiler: () => new MssqlQueryCompiler(),
  };
}

// connect opens a driver handle for url and returns the `database` option for Better Auth.
function connect(dialect, url, config) {
  if (dialect === "mssql") {
    return { database: { dialect: fakeMssql(), type: "mssql" }, exec: async () => {}, close: async () => {} };
  }
  if (dialect === "sqlite") {
    const db = new Database(url);
    db.pragma("foreign_keys = ON");
    return { database: db, exec: async (sql) => db.exec(sql), close: async () => db.close() };
  }
  if (dialect === "postgres") {
    const u = new URL(url);
    u.searchParams.delete("search_path");
    const options = config.searchPath ? `-c search_path=${config.searchPath}` : undefined;
    const pool = new pg.Pool({ connectionString: u.toString(), options });
    const database = config.schemaName
      ? { dialect: new PostgresDialect({ pool }), type: "postgres", schemaName: config.schemaName }
      : pool;
    return { database, exec: async (sql) => pool.query(sql), close: async () => pool.end() };
  }
  const pool = mysql.createPool({ uri: url, connectionLimit: 2 });
  return { database: pool, exec: async (sql) => pool.query(sql), close: async () => pool.end() };
}

// ---- planning -------------------------------------------------------------------------

function fieldNames(list) {
  return list.map((t) => ({ table: t.table, fields: Object.keys(t.fields) }));
}

async function plan(database, spec, { reportUnsafe = false } = {}) {
  const warnings = [];
  const options = {
    ...toOptions(spec),
    database,
    logger: { level: "warn", log: (level, message) => level === "warn" && warnings.push(message) },
  };
  try {
    const m = await getMigrations(options, { throwOnUnsafe: !reportUnsafe });
    return {
      result: {
        sql: await m.compileMigrations(),
        toBeCreated: fieldNames(m.toBeCreated),
        toBeAdded: fieldNames(m.toBeAdded),
        toBeAddedIndexes: m.toBeAddedIndexes.map(({ table, name, index }) => ({
          table,
          name,
          columns: [...index.columns],
          unique: index.unique ?? false,
        })),
        unsafeChanges: m.unsafeChanges,
        schemaProblems: m.schemaProblems,
        warnings,
      },
      run: m.runMigrations,
    };
  } catch (error) {
    return { result: { error: `${error.constructor.name}: ${error.message}`, warnings } };
  }
}

async function apply(database, spec) {
  const { result, run } = await plan(database, spec);
  if (result.error) throw new Error(result.error);
  await run();
}

async function fixture(config, dialect) {
  if (dialect === "mssql") {
    const { result } = await plan(connect("mssql", "", config).database, config.options, { reportUnsafe: config.reportUnsafe });
    return { config: config.name, dialect, ...result };
  }
  const db = await createDatabase(dialect);
  const conn = connect(dialect, db.url, config);
  try {
    if (config.base) await apply(conn.database, config.base);
    for (const sql of config.setup?.[dialect] ?? []) await conn.exec(sql);
    const { result, run } = await plan(conn.database, config.options, { reportUnsafe: config.reportUnsafe });
    if (run && !(config.skipApply ?? []).includes(dialect)) {
      try {
        await run();
      } catch (error) {
        throw new Error(`${config.name} / ${dialect}: applying the plan failed: ${error.message}`);
      }
      const again = await plan(conn.database, config.options);
      result.afterApply = again.result.error ?? again.result.sql;
      result.afterApplyWarnings = again.result.warnings;
    }
    return { config: config.name, dialect, ...result };
  } finally {
    await conn.close();
    await db.drop();
  }
}

async function generate() {
  const out = [];
  for (const config of configs) {
    // SQL Server has no test database: its plans are generated for an empty database (setup
    // SQL is not run) through a driver that returns no rows.
    const mssql = !config.dialects && !config.base && !config.setup?.mssql ? ["mssql"] : [];
    for (const dialect of [...(config.dialects ?? DIALECTS), ...mssql]) {
      out.push(await fixture(config, dialect));
      console.error(`${config.name} / ${dialect}`);
    }
  }
  writeFileSync(new URL("fixtures.json", testdata), JSON.stringify({ betterAuth: "1.7.7", fixtures: out }, null, 2) + "\n");
  console.error("wrote adapter/sqladapter/migration/testdata/fixtures.json");
}

// crosscheck reads [{config, dialect, url, action: "apply" | "plan"}] on stdin and prints
// one result per job: {ok: true} for apply, the plan for plan, or {error}.
async function crosscheck() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const jobs = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  const results = [];
  for (const job of jobs) {
    const config = configs.find((c) => c.name === job.config);
    const spec = job.spec ?? config.options;
    const conn = connect(job.dialect, job.url, config ?? {});
    try {
      if (job.action === "apply") {
        await apply(conn.database, spec);
        results.push({ ok: true });
      } else {
        results.push((await plan(conn.database, spec)).result);
      }
    } catch (error) {
      results.push({ error: String(error?.message ?? error) });
    } finally {
      await conn.close();
    }
  }
  process.stdout.write(JSON.stringify(results));
}

if (process.argv[2] === "crosscheck") await crosscheck();
else await generate();
