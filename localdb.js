// Chhota file-based database (MongoDB jaisa API) — jab MONGO_URI na ho tab use hota hai.
// Data DATA_DIR/<collection>.json me save hota hai.
const fs = require('fs');
const path = require('path');

function matchVal(docVal, cond) {
  if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
    return Object.entries(cond).every(([op, v]) => {
      if (op === '$exists') return (docVal !== undefined) === !!v;
      if (op === '$gte') return docVal !== undefined && docVal >= v;
      if (op === '$lte') return docVal !== undefined && docVal <= v;
      if (op === '$ne') return docVal !== v;
      return false;
    });
  }
  return docVal === cond;
}
const matches = (doc, q = {}) => Object.entries(q).every(([k, c]) => matchVal(doc[k], c));

class Cursor {
  constructor(rows) { this.rows = rows; }
  sort(spec) {
    const keys = Object.entries(spec);
    this.rows.sort((a, b) => {
      for (const [k, dir] of keys) {
        if (a[k] === b[k]) continue;
        return (a[k] > b[k] ? 1 : -1) * dir;
      }
      return 0;
    });
    return this;
  }
  limit(n) { this.rows = this.rows.slice(0, n); return this; }
  async toArray() { return this.rows; }
}

class Collection {
  constructor(file) {
    this.file = file;
    try { this.docs = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { this.docs = []; }
  }
  save() { fs.writeFileSync(this.file, JSON.stringify(this.docs, null, 2)); }
  find(q) { return new Cursor(this.docs.filter(d => matches(d, q)).map(d => ({ ...d }))); }
  async findOne(q) { const d = this.docs.find(d => matches(d, q)); return d ? { ...d } : null; }
  async countDocuments(q) { return this.docs.filter(d => matches(d, q)).length; }
  async insertOne(doc) { this.docs.push({ ...doc }); this.save(); return { acknowledged: true }; }
  async updateOne(q, upd, opts = {}) {
    let d = this.docs.find(d => matches(d, q));
    if (!d && opts.upsert) { d = { ...q }; this.docs.push(d); }
    if (d && upd.$set) Object.assign(d, upd.$set);
    this.save();
    return { acknowledged: true };
  }
  async deleteOne(q) {
    const i = this.docs.findIndex(d => matches(d, q));
    if (i >= 0) this.docs.splice(i, 1);
    this.save();
    return { acknowledged: true };
  }
  async deleteMany(q) { this.docs = this.docs.filter(d => !matches(d, q)); this.save(); return { acknowledged: true }; }
}

module.exports = function createLocalDb(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const cache = {};
  const seqFile = path.join(dir, 'counters.json');
  return {
    collection: name => cache[name] || (cache[name] = new Collection(path.join(dir, name + '.json'))),
    // atomic-enough counter (single process)
    nextSeq: async name => {
      let c = {}; try { c = JSON.parse(fs.readFileSync(seqFile, 'utf8')); } catch {}
      c[name] = (c[name] || 0) + 1; fs.writeFileSync(seqFile, JSON.stringify(c)); return c[name];
    }
  };
};
