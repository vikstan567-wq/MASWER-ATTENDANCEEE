// PostgreSQL (Supabase) adapter — MongoDB jaisa chhota API, taaki server.js ka logic same rahe.
const { Pool } = require('pg');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS employees (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, mobile TEXT, role TEXT DEFAULT 'employee', created_at TEXT
);
CREATE TABLE IF NOT EXISTS attendance (
  id TEXT PRIMARY KEY, emp_id TEXT NOT NULL, emp_name TEXT, date TEXT NOT NULL, time TEXT, shift TEXT, status TEXT,
  device_id TEXT, marked_at TEXT, check_out TEXT, check_out_at TEXT, total_hours TEXT,
  manually_added BOOLEAN, edited_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_att_emp_date ON attendance (emp_id, date);
CREATE INDEX IF NOT EXISTS idx_att_date ON attendance (date);
CREATE INDEX IF NOT EXISTS idx_att_device ON attendance (device_id, date);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value JSONB);
CREATE TABLE IF NOT EXISTS it_users (id TEXT PRIMARY KEY, name TEXT NOT NULL, salt TEXT, pass_hash TEXT, created_at TEXT);
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS unlocked_by TEXT;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS unlocked_at TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS location_id TEXT;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS location_id TEXT;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS location_name TEXT;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS added_by TEXT;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS edited_by TEXT;
CREATE TABLE IF NOT EXISTS locations (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, lat DOUBLE PRECISION, lng DOUBLE PRECISION, radius INTEGER DEFAULT 100,
  created_by TEXT, created_at TEXT, updated_at TEXT
);
ALTER TABLE employees ADD COLUMN IF NOT EXISTS department TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS location_ids JSONB;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS department TEXT;
CREATE TABLE IF NOT EXISTS counters (key TEXT PRIMARY KEY, n INTEGER NOT NULL);
ALTER TABLE counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS designation TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS joining_date TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS monthly_salary DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS active BOOLEAN;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS photo_doc_id TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS emp_no TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS basic DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS da DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS hra DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS other_allow DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS project_per_day DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS travel_per_day DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS food_per_day DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS pf_amount DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS esi_amount DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS prof_tax DOUBLE PRECISION;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_name TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_account TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS pan_number TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS esi_no TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS pf_no TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS uan_no TEXT;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS leave_opening DOUBLE PRECISION;
CREATE TABLE IF NOT EXISTS payadj (id TEXT PRIMARY KEY, emp_id TEXT NOT NULL, month TEXT NOT NULL, leave_availed DOUBLE PRECISION, leave_wages DOUBLE PRECISION, extra_days DOUBLE PRECISION, updated_by TEXT, updated_at TEXT);
ALTER TABLE payadj ADD COLUMN IF NOT EXISTS extra_days DOUBLE PRECISION;
ALTER TABLE payadj ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS edit_reason TEXT;
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY, emp_id TEXT NOT NULL, type TEXT, file_name TEXT, mime TEXT, size INTEGER, path TEXT,
  status TEXT, uploaded_by TEXT, uploaded_at TEXT, replaced_at TEXT
);
ALTER TABLE documents ADD COLUMN IF NOT EXISTS replace_of TEXT;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS label TEXT;
ALTER TABLE documents ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE payslips ADD COLUMN IF NOT EXISTS delivered_at TEXT;
ALTER TABLE payslips ADD COLUMN IF NOT EXISTS delivered_by TEXT;
CREATE INDEX IF NOT EXISTS idx_docs_emp ON documents (emp_id);
CREATE TABLE IF NOT EXISTS payslips (
  id TEXT PRIMARY KEY, emp_id TEXT NOT NULL, month TEXT NOT NULL, version INTEGER, snapshot JSONB, net DOUBLE PRECISION,
  finalized BOOLEAN, finalized_at TEXT, finalized_by TEXT, generated_at TEXT, generated_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_payslips_month ON payslips (month);
CREATE TABLE IF NOT EXISTS advances (id TEXT PRIMARY KEY, emp_id TEXT NOT NULL, month TEXT NOT NULL, amount DOUBLE PRECISION, note TEXT, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, at TEXT, by_id TEXT, by_role TEXT, action TEXT, target TEXT, details JSONB, reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log (at);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE payslips ENABLE ROW LEVEL SECURITY;
ALTER TABLE advances ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_by TEXT, created_at TEXT);
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS client TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS state_code TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS state_name TEXT;
CREATE TABLE IF NOT EXISTS managers (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, salt TEXT, pass_hash TEXT, state_codes JSONB DEFAULT '[]'::jsonb, created_by TEXT, created_at TEXT
);
ALTER TABLE managers ENABLE ROW LEVEL SECURITY;
ALTER TABLE locations ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE locations ADD COLUMN IF NOT EXISTS project_id TEXT;
ALTER TABLE locations ADD COLUMN IF NOT EXISTS project_name TEXT;
CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, salt TEXT, pass_hash TEXT, all_locations BOOLEAN DEFAULT FALSE,
  locations JSONB DEFAULT '[]'::jsonb, created_by TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_att_loc ON attendance (location_id, date);
ALTER TABLE locations ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS departments JSONB;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS can_salary BOOLEAN;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS can_docs BOOLEAN;
ALTER TABLE admins ADD COLUMN IF NOT EXISTS can_edit_punch BOOLEAN;
ALTER TABLE it_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE employees ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
`;

const snake = k => k.replace(/[A-Z]/g, c => '_' + c.toLowerCase());
const camel = k => k.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
const ident = k => { if (!/^[A-Za-z]+$/.test(k)) throw new Error('bad column ' + k); return '"' + snake(k) + '"'; };

function rowToDoc(row) {
  const d = {};
  for (const [k, v] of Object.entries(row)) if (v !== null && v !== undefined) d[camel(k)] = v;
  return d;
}

function buildWhere(q = {}, params = []) {
  const parts = [];
  for (const [k, c] of Object.entries(q)) {
    const col = ident(k);
    if (c && typeof c === 'object' && !Array.isArray(c)) {
      for (const [op, v] of Object.entries(c)) {
        if (op === '$exists') parts.push(`${col} IS ${v ? 'NOT ' : ''}NULL`);
        else if (op === '$gte') { params.push(v); parts.push(`${col} >= $${params.length}`); }
        else if (op === '$lte') { params.push(v); parts.push(`${col} <= $${params.length}`); }
        else throw new Error('unsupported op ' + op);
      }
    } else if (c === undefined) parts.push('FALSE');
    else if (c === null) parts.push(`${col} IS NULL`);
    else { params.push(c); parts.push(`${col} = $${params.length}`); }
  }
  return parts.length ? 'WHERE ' + parts.join(' AND ') : '';
}

class Cursor {
  constructor(pool, table, q) { this.pool = pool; this.table = table; this.q = q; this._sort = null; this._limit = null; }
  sort(spec) { this._sort = spec; return this; }
  limit(n) { this._limit = n; return this; }
  async toArray() {
    const params = [];
    let sql = `SELECT * FROM ${this.table} ${buildWhere(this.q, params)}`;
    if (this._sort) sql += ' ORDER BY ' + Object.entries(this._sort).map(([k, d]) => `${ident(k)} ${d < 0 ? 'DESC' : 'ASC'}`).join(', ');
    if (this._limit) sql += ' LIMIT ' + parseInt(this._limit);
    const r = await this.pool.query(sql, params);
    return r.rows.map(rowToDoc);
  }
}

class Collection {
  constructor(pool, table) { this.pool = pool; this.table = table; }
  find(q) { return new Cursor(this.pool, this.table, q); }
  async findOne(q) { const r = await this.find(q).limit(1).toArray(); return r[0] || null; }
  async countDocuments(q) {
    const params = [];
    const r = await this.pool.query(`SELECT COUNT(*)::int AS n FROM ${this.table} ${buildWhere(q, params)}`, params);
    return r.rows[0].n;
  }
  _val(k, v) { return (k === 'value' || (v && typeof v === 'object')) ? JSON.stringify(v) : v; }
  async insertOne(doc) {
    const keys = Object.keys(doc).filter(k => k !== '_id' && doc[k] !== undefined);
    const sql = `INSERT INTO ${this.table} (${keys.map(ident).join(',')}) VALUES (${keys.map((_, i) => '$' + (i + 1)).join(',')})`;
    await this.pool.query(sql, keys.map(k => this._val(k, doc[k])));
    return { acknowledged: true };
  }
  async updateOne(q, upd, opts = {}) {
    const set = upd.$set || {};
    const keys = Object.keys(set);
    if (keys.length) {
      const params = keys.map(k => this._val(k, set[k]));
      const sets = keys.map((k, i) => `${ident(k)} = $${i + 1}`).join(', ');
      const where = buildWhere(q, params);
      const r = await this.pool.query(`UPDATE ${this.table} SET ${sets} ${where}`, params);
      if (r.rowCount > 0) return { acknowledged: true };
    }
    if (opts.upsert) await this.insertOne({ ...q, ...set });
    return { acknowledged: true };
  }
  async deleteOne(q) { return this.deleteMany(q); } // queries are always by unique key
  async deleteMany(q) {
    const params = [];
    await this.pool.query(`DELETE FROM ${this.table} ${buildWhere(q, params)}`, params);
    return { acknowledged: true };
  }
}

module.exports = async function createPgDb(connectionString) {
  const local = /localhost|127\.0\.0\.1/.test(connectionString);
  const pool = new Pool({ connectionString, ssl: local ? false : { rejectUnauthorized: false }, max: (process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME) ? 1 : 8 });
  // Run the schema only when it changed (keeps cold starts fast) and never from two instances at once.
  let ver = 0; for (let i = 0; i < SCHEMA.length; i++) ver = (ver * 31 + SCHEMA.charCodeAt(i)) % 2147483647;
  let done = false;
  try { const r = await pool.query("SELECT n FROM counters WHERE key = 'schema_ver'"); done = r.rows[0] && r.rows[0].n === ver; } catch (e) {}
  if (!done) {
    const cl = await pool.connect();
    try {
      await cl.query('SELECT pg_advisory_lock(727401)');
      let again = false;
      try { const r = await cl.query("SELECT n FROM counters WHERE key = 'schema_ver'"); again = r.rows[0] && r.rows[0].n === ver; } catch (e) {}
      if (!again) {
        await cl.query(SCHEMA);
        await cl.query("INSERT INTO counters (key, n) VALUES ('schema_ver', $1) ON CONFLICT (key) DO UPDATE SET n = $1", [ver]);
      }
    } finally { try { await cl.query('SELECT pg_advisory_unlock(727401)'); } catch (e) {} cl.release(); }
  }
  return {
    collection: name => new Collection(pool, name),
    // safe even if two admins add employees at the same moment
    nextSeq: async name => (await pool.query('INSERT INTO counters (key, n) VALUES ($1, 1) ON CONFLICT (key) DO UPDATE SET n = counters.n + 1 RETURNING n', [name])).rows[0].n
  };
};
