const express = require('express');
const cors = require('cors');
const path = require('path');
const QRCode = require('qrcode');
const XLSX = require('xlsx');
let MongoClient; try { ({ MongoClient } = require('mongodb')); } catch (e) { /* optional */ }
const crypto = require('crypto');
 
const app = express();
const PORT = process.env.PORT || 3000;
const EDIT_PIN = process.env.EDIT_PIN || '011216';
 
app.use(cors());
app.use(express.json());

app.set('trust proxy', 1);
let dbReady = null;
app.use('/api', async (req, res, next) => {
  try { dbReady = dbReady || connectDB(); await dbReady; next(); }
  catch (e) { dbReady = null; console.error('DB error:', e.message); res.status(503).json({ error: 'Could not connect to the database: ' + e.message }); }
});
process.on('unhandledRejection', e => console.error('Unhandled:', e && e.message));

// ── ADMIN AUTH (signed cookie) ─────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const sign = v => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('hex');
function makeToken(id, role, proj = '') { const exp = Date.now() + 12 * 3600 * 1000; const p = `${id}|${role}|${exp}|${proj}`; return `${p}.${sign(p)}`; }
function setSession(res, req, id, role, proj) {
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `mw_admin=${encodeURIComponent(makeToken(id, role, proj))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200${secure}`);
}
// cookie padh kar { id, role, proj } deta hai (signature + expiry check ke baad)
function readSession(req) {
  const t = readCookie(req, 'mw_admin');
  if (!t) return null;
  const i = t.lastIndexOf('.');
  const p = t.slice(0, i), sig = t.slice(i + 1);
  const good = Buffer.from(sign(p)), got = Buffer.from(sig);
  if (good.length !== got.length || !crypto.timingSafeEqual(good, got)) return null;
  const [id, role, exp, proj] = p.split('|');
  if (!(parseInt(exp) > Date.now())) return null;
  return { id, role, proj: proj || '' };
}
async function baseScope(id) {
  const ad = await db.collection('admins').findOne({ id });
  if (ad) return { scope: ad.allLocations ? '*' : (ad.locations || []), name: ad.name, departments: ad.departments || [], perms: { salary: true, docs: true, editPunch: true } };
  const emp = await db.collection('employees').findOne({ id, role: 'admin' });
  return emp ? { scope: '*', name: emp.name, perms: { salary: true, docs: true, editPunch: true } } : null;
}
// is admin ke liye kaun-kaun se projects hain (scope ke andar)
async function adminProjects(scope) {
  const locs = await db.collection('locations').find({}).toArray();
  const ps = await db.collection('projects').find({}).toArray();
  return ps.filter(p => locs.some(l => l.projectId === p.id && (scope === '*' || scope.includes(l.id)))).map(p => ({ id: p.id, name: p.name }));
}
function readCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
// roles: 'it' (poora access: sab locations, admins, geofence, edit) | 'admin' (sirf apni locations — req.scope)
function authWith(roles) {
  return async (req, res, next) => {
    try {
      const ses = readSession(req);
      if (ses) {
        const { id, role, proj } = ses;
        if (!roles.includes(role)) return res.status(403).json({ error: 'You do not have permission for this action' });
        let scope = '*', name = id;
        if (role === 'it') {
          const it = await db.collection('it_users').findOne({ id });
          if (!it) return res.status(401).json({ error: 'Login required' });
          name = it.name;
        } else if (role === 'manager') {
          const m = await db.collection('managers').findOne({ id });
          if (!m) return res.status(401).json({ error: 'Login required' });
          name = m.name; scope = await managerScope(m); req.deptScope = []; req.perms = {}; req.stateCodes = m.stateCodes || [];
        } else {
          if (proj === '?') return res.status(403).json({ error: 'Please choose a Project ID (or ALL) first', code: 'project_required' });
          const b = await baseScope(id);
          if (!b) return res.status(401).json({ error: 'Login required' });
          name = b.name; scope = b.scope; req.deptScope = b.departments || []; req.perms = b.perms || { salary: true, docs: true, editPunch: true };
          if (proj && proj !== 'ALL') { // ek project tak seemit
            const ids = (await db.collection('locations').find({}).toArray()).filter(l => l.projectId === proj).map(l => l.id);
            scope = scope === '*' ? ids : ids.filter(i => scope.includes(i));
          }
        }
        req.perms = role === 'it' ? { salary: false, docs: false, editPunch: true, settings: false } : (req.perms || {}); // salary / documents = HR work only
        req.user = { id, role, name, project: role === 'admin' ? (proj || 'ALL') : undefined }; req.scope = scope;
        return next();
      }
      res.status(401).json({ error: 'Login required' });
    } catch (e) { console.error('auth error:', e.message); res.status(500).json({ error: 'Server error' }); }
  };
}
const requireIT = authWith(['it']);
const requireStaff = authWith(['admin', 'it']);
const requireView = authWith(['admin', 'it', 'manager']); // read-only views (Site Managers can use these)
// a Site Manager sees every location of every project in his states (new projects are included automatically)
async function managerScope(m) {
  const codes = new Set(m.stateCodes || []);
  const pids = new Set((await db.collection('projects').find({}).toArray()).filter(p => codes.has(p.stateCode)).map(p => p.id));
  return (await db.collection('locations').find({}).toArray()).filter(l => pids.has(l.projectId)).map(l => l.id);
}
const hasPerm = (req, p) => !!(req.perms && req.perms[p]);
const noPerm = res => res.status(403).json({ error: 'You do not have permission for this action' });
// audit trail — who changed what, when, and why
async function audit(req, action, target, details, reason) {
  try {
    await db.collection('audit_log').insertOne({ id: newId('A'), at: new Date().toISOString(), byId: req.user && req.user.id, byRole: req.user && req.user.role, action, target: target || undefined, details: details || undefined, reason: reason || undefined });
  } catch (e) { console.error('audit failed:', e.message); }
}
const needReason = v => String(v || '').trim().length >= 3;
// next unique number (database counter) — used for EMP001, EMP002 ...
async function nextSeq(name) { return db.nextSeq(name); }
// is employee-month finalized (payslip locked)?
async function isLocked(empId, date) {
  if (!empId || !date) return false;
  const p = await db.collection('payslips').findOne({ id: `PS-${String(date).slice(0, 7)}-${empId}` });
  return !!(p && p.finalized);
}
// night-shift aware punch lookup: today's record, or an open one from yesterday
const OPEN_MAX_HOURS = 20, REPUNCH_GAP_HOURS = 6;
const yesterday = () => new Date(Date.now() - 24 * 3600 * 1000).toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
async function findActive(empId) {
  const rec = await db.collection('attendance').findOne({ empId, date: today() });
  if (rec) return rec;
  const prev = await db.collection('attendance').findOne({ empId, date: yesterday(), checkOut: { $exists: false } });
  if (prev && prev.markedAt && Date.now() - new Date(prev.markedAt).getTime() < OPEN_MAX_HOURS * 3600 * 1000) return prev;
  return null;
}
// just finished a (night) shift a few hours ago → do not allow a fresh punch-in
async function recentlyClosed(empId) {
  const prev = await db.collection('attendance').findOne({ empId, date: yesterday() });
  if (prev && prev.checkOut && prev.checkOutAt && Date.now() - new Date(prev.checkOutAt).getTime() < REPUNCH_GAP_HOURS * 3600 * 1000) return prev;
  return null;
}
function hashPassword(pw, salt) { return crypto.scryptSync(String(pw), salt, 32).toString('hex'); }
function checkPassword(pw, user) {
  if (!pw || !user || !user.salt || !user.passHash) return false;
  const a = Buffer.from(hashPassword(pw, user.salt)), b = Buffer.from(user.passHash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// scope helpers — IT / super admin = '*' (sab), baaki sirf apni locations
const inScope = (req, locId) => req.scope === '*' || (!!locId && req.scope.includes(locId));
function scopeFilter(req) {
  // ?location=ID  ya  ?location=ID1,ID2 (ek project ki sab locations);  ?department=Name
  const want = req.query.location && req.query.location !== 'all' ? new Set(String(req.query.location).split(',')) : null;
  const dep = req.query.department && req.query.department !== 'all' ? String(req.query.department) : null;
  const ds = req.deptScope && req.deptScope.length ? req.deptScope : null;
  return d => {
    const ls = [d.locationId || '', ...(Array.isArray(d.locationIds) ? d.locationIds : [])];
    if (want && !ls.some(l => want.has(l))) return false;
    if (req.scope !== '*' && !ls.some(l => req.scope.includes(l))) return false;
    if (dep && (d.department || '') !== dep) return false;
    if (ds && !ds.includes(d.department || '')) return false;
    return true;
  };
}
// PIN: IT ko PIN nahi lagta; Admin ko lagta hai
const pinOk = (req, pin) => req.user.role === 'it' || pin === EDIT_PIN;
// admin ka mobile (= uska password) sirf IT ko dikhta hai
const staffView = (e, req) => (req.user && req.user.role !== 'it' && e.role === 'admin') ? { ...e, mobile: '' } : e;
const publicEmp = e => (e && e.role === 'admin') ? { ...e, mobile: '' } : e;
const fs = require('fs');
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(__dirname, 'public');
app.use(express.static(fs.existsSync(PUBLIC_DIR) ? PUBLIC_DIR : __dirname));
 
// ── MongoDB Connection ─────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;
const DATABASE_URL = process.env.DATABASE_URL; // Supabase / PostgreSQL
let db;
let dbKind = 'Local file';
 
async function connectDB() {
  if (DATABASE_URL) {
    db = await require('./pgdb')(DATABASE_URL);
    dbKind = 'Supabase (PostgreSQL)';
    console.log('✅ Supabase (PostgreSQL) connected!');
  } else if (MONGO_URI) {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    db = client.db('maswer_attend');
    db.nextSeq = async name => { const r = await db.collection('counters').findOneAndUpdate({ _id: name }, { $inc: { n: 1 } }, { upsert: true, returnDocument: 'after' }); return (r && r.value ? r.value : r).n; };
    dbKind = 'MongoDB';
    console.log('✅ MongoDB connected!');
  } else {
    const dir = process.env.DATA_DIR || path.join(__dirname, 'data');
    db = require('./localdb')(dir);
    console.log('💾 MONGO_URI not found — using local data folder: ' + dir);
  }
  // pehla IT login (IT sab kuch manage karta hai: admins, locations, attendance)
  if (await db.collection('it_users').countDocuments() === 0) {
    const id = String(process.env.IT_ID || 'IT001').toUpperCase();
    const pw = process.env.IT_PASSWORD || 'ChangeMe@123';
    const salt = crypto.randomBytes(16).toString('hex');
    await db.collection('it_users').insertOne({ id, name: 'IT Head', salt, passHash: hashPassword(pw, salt), createdAt: new Date().toISOString() });
    console.log(process.env.IT_PASSWORD ? `✅ IT login created: ${id}` : `⚠️  IT login ${id} / ChangeMe@123 — change the password immediately (or set the IT_PASSWORD env variable)`);
  }
  // purana default "Vivek Singh" (MW113761) entry hata do — ab admins IT banata hai
  const old = await db.collection('employees').findOne({ id: 'MW113761', role: 'admin' });
  if (old && old.name === 'Vivek Singh' && await db.collection('it_users').countDocuments() > 0) {
    await db.collection('employees').deleteOne({ id: 'MW113761' });
    await db.collection('attendance').deleteMany({ empId: 'MW113761' });
    console.log('🧹 Old default admin entry (MW113761) removed.');
  }
  // purani single location -> locations list me
  if (await db.collection('locations').countDocuments() === 0) {
    const old = await db.collection('settings').findOne({ key: 'location' });
    if (old && old.value && old.value.lat) {
      const loc = { id: 'L' + Date.now().toString(36), name: old.value.name || 'Office', lat: old.value.lat, lng: old.value.lng, radius: old.value.radius || 100, createdAt: new Date().toISOString() };
      await db.collection('locations').insertOne(loc);
      const emps = await db.collection('employees').find({ role: 'employee' }).toArray();
      for (const e of emps) await db.collection('employees').updateOne({ id: e.id }, { $set: { locationId: loc.id } });
      await db.collection('settings').deleteOne({ key: 'location' });
      console.log('✅ Old location migrated: ' + loc.name);
    }
  }
}
 
// ── Helpers ────────────────────────────────────────────────
function today() { return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' }); }
function nowTime() { return new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true, timeZone: 'Asia/Kolkata' }); }
 
function convertTo24(timeStr) {
  if (!timeStr) return '00:00';
  const upper = timeStr.trim().toUpperCase();
  const match = upper.match(/(\d{1,2}):(\d{2})\s*(AM|PM)?/);
  if (!match) return '00:00';
  let hours = parseInt(match[1]);
  const minutes = match[2];
  const modifier = match[3];
  if (modifier === 'PM' && hours !== 12) hours += 12;
  if (modifier === 'AM' && hours === 12) hours = 0;
  return `${String(hours).padStart(2,'0')}:${minutes}`;
}
 
const SHIFTS = {
  'A': { start: '06:30', label: 'A Shift (6:30 AM)' },
  'B': { start: '15:15', label: 'B Shift (3:15 PM)' },
  'G': { start: '08:45', label: 'G Shift (8:45 AM)' },
  'C': { start: '23:45', label: 'C Shift (11:45 PM)' }
};
 
function checkShiftStatus(shift, checkInTime24) {
  const shiftDef = SHIFTS[shift?.toUpperCase()];
  if (!shiftDef) return 'present';
  const [sh, sm] = shiftDef.start.split(':').map(Number);
  const [ch, cm] = checkInTime24.split(':').map(Number);
  return (ch * 60 + cm) <= (sh * 60 + sm + 10) ? 'present' : 'late';
}
 
function calcTotalHours(inTime24, outTime24, date) {
  try {
    let inMs = new Date(`${date}T${inTime24}:00`).getTime();
    let outMs = new Date(`${date}T${outTime24}:00`).getTime();
    if (outMs < inMs) outMs += 24 * 60 * 60 * 1000;
    const diffMs = outMs - inMs;
    if (diffMs <= 0) return 'N/A';
    return `${Math.floor(diffMs/3600000)}h ${Math.floor((diffMs%3600000)/60000)}m`;
  } catch(e) { return 'N/A'; }
}
 
// Device ID — from client localStorage (reliable across IP changes)
function getDeviceId(req) {
  // Try from body first, then query param
  return req.body?.deviceId || req.query?.did || 
    crypto.createHash('md5').update((req.headers['user-agent']||'') + (req.headers['x-forwarded-for']||'')).digest('hex');
}
 

// ── GEOFENCE (server-side) ─────────────────────────────────
function distMeters(lat1, lng1, lat2, lng2) {
  const R = 6371000, rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad, dLng = (lng2 - lng1) * rad;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLng / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}
// employee kin locations par attendance laga sakta hai (primary + extra)
const allowedLocs = emp => [emp.locationId, ...(Array.isArray(emp.locationIds) ? emp.locationIds : [])].filter(Boolean);
// jis QR se scan hua wo allowed ho to wahi, warna primary location
const scanLoc = (emp, body) => (body && body.locId && allowedLocs(emp).includes(String(body.locId))) ? String(body.locId) : (emp.locationId || '');
// null = allowed, otherwise { error, message }. Employee ki apni location (emp.locationId) ka geofence lagta hai.
async function geoGuard(emp, body) {
  const lid = scanLoc(emp, body);
  if (!lid) return null; // IT ne location assign nahi ki — geofence nahi
  const loc = await db.collection('locations').findOne({ id: lid });
  if (!loc || !loc.lat || !loc.lng) return null;
  const bp = await db.collection('settings').findOne({ key: 'location_bypass' });
  if (bp && (bp.value || []).some(e => e.id === emp.id)) return null; // bypass employee
  const lat = parseFloat(body.lat), lng = parseFloat(body.lng);
  if (!isFinite(lat) || !isFinite(lng)) return { error: 'location_required', message: 'Location not received — please turn on the location on your phone and try again.' };
  const dist = distMeters(lat, lng, loc.lat, loc.lng);
  const slack = Math.min(parseFloat(body.accuracy) || 0, 50); // GPS ki galti ka thoda allowance
  if (dist - slack > (loc.radius || 100)) return { error: 'out_of_range', message: `You are ${Math.round(dist)}m away from ${loc.name || 'office'} (limit ${loc.radius || 100}m).` };
  return null;
}
// Location ke QR se scan hua ho to employee usi location ka hona chahiye
async function wrongLoc(emp, body) {
  const q = String(body.locId || '');
  if (!q || emp.role === 'admin') return null;
  const loc = await db.collection('locations').findOne({ id: q });
  if (!loc) return { error: 'bad_qr', message: 'This QR code is no longer valid. Please scan a new QR code.' };
  if (!allowedLocs(emp).includes(q)) return { error: 'wrong_location', message: `You are not an employee of "${loc.name}". Please scan the QR code for your own location.` };
  return null;
}
async function locName(id) { if (!id) return ''; const l = await db.collection('locations').findOne({ id }); return l ? l.name : ''; }

// ── EMPLOYEE ROUTES ────────────────────────────────────────
app.get('/api/employees', requireStaff, async (req, res) => {
  const emps = (await db.collection('employees').find({}).toArray()).filter(scopeFilter(req));
  const locs = await db.collection('locations').find({}).toArray();
  const nm = id => (locs.find(l => l.id === id) || {}).name || '';
  res.json(emps.map(e => { const v = { ...staffView(e, req), locationName: nm(e.locationId), extraLocationNames: (e.locationIds || []).map(nm).filter(Boolean) }; if (!hasPerm(req, 'salary')) delete v.monthlySalary; return v; }));
});
// departments list (scope ke andar)
app.get('/api/departments', requireView, async (req, res) => {
  const emps = (await db.collection('employees').find({}).toArray()).filter(scopeFilter({ ...req, query: {} }));
  res.json([...new Set(emps.map(e => e.department).filter(Boolean))].sort());
});
const cleanDept = v => String(v || '').trim().slice(0, 40);
 
// clean employee master fields
function cleanEmpFields(b, req) {
  const out = {}, err = [];
  if (b.name !== undefined) { const v = String(b.name).trim().slice(0, 80); if (!v) err.push('Name is required'); else out.name = v; }
  if (b.mobile !== undefined) { const v = String(b.mobile).trim().slice(0, 20); if (v && !/^[0-9+\-\s()]{6,20}$/.test(v)) err.push('Phone number looks invalid'); else out.mobile = v || 'N/A'; }
  if (b.designation !== undefined) out.designation = String(b.designation).trim().slice(0, 60);
  if (b.joiningDate !== undefined) { const v = String(b.joiningDate).trim(); if (v && !/^\d{4}-\d{2}-\d{2}$/.test(v)) err.push('Joining date must be YYYY-MM-DD'); else out.joiningDate = v; }
  if (b.monthlySalary !== undefined && hasPerm(req, 'salary')) {
    const v = b.monthlySalary === '' || b.monthlySalary === null ? null : Number(b.monthlySalary);
    if (v !== null && (!isFinite(v) || v < 0 || v > 100000000)) err.push('Monthly salary must be a positive number'); else out.monthlySalary = v === null ? 0 : v;
  }
  return { out, err };
}
app.post('/api/employees', requireStaff, async (req, res) => {
  let locationId = req.body.locationId || '';
  const department = cleanDept(req.body.department);
  const { out, err } = cleanEmpFields({ ...req.body, name: req.body.name || '' }, req);
  if (err.length) return res.status(400).json({ error: err[0] });
  if (req.scope !== '*' && !locationId && req.scope.length === 1) locationId = req.scope[0];
  if (req.scope !== '*' && !inScope(req, locationId)) return res.status(403).json({ error: 'You do not have permission to add employees to this location' });
  if (req.deptScope && req.deptScope.length && !req.deptScope.includes(department)) return res.status(403).json({ error: 'You can only add employees to your own department(s)' });
  if (locationId && !await db.collection('locations').findOne({ id: locationId })) return res.status(400).json({ error: 'Location not found' });
  // auto Employee ID: EMP001, EMP002 ... (database counter — safe even if two admins add at once)
  let id = '';
  for (let i = 0; i < 50; i++) {
    id = 'EMP' + String(await nextSeq('emp')).padStart(3, '0');
    if (!(await idTaken(id))) break;
    id = '';
  }
  if (!id) return res.status(500).json({ error: 'Could not generate a unique Employee ID. Please try again.' });
  const emp = { id, name: out.name, mobile: out.mobile || 'N/A', role: 'employee', active: true, locationId: locationId || undefined, department: department || undefined,
    designation: out.designation || undefined, joiningDate: out.joiningDate || undefined, monthlySalary: out.monthlySalary !== undefined ? out.monthlySalary : undefined, createdAt: new Date().toISOString() };
  await db.collection('employees').insertOne(emp);
  await audit(req, 'employee.create', id, { name: emp.name, department: emp.department, locationId: emp.locationId });
  if (!hasPerm(req, 'salary')) delete emp.monthlySalary;
  res.json({ success: true, employee: emp });
});

// employee ki location badlo (IT: kisi bhi; Admin: apni locations ke andar)
app.post('/api/employees/:id/location', requireStaff, async (req, res) => {
  const emp = await db.collection('employees').findOne({ id: req.params.id.toUpperCase() });
  if (!emp || emp.role === 'admin') return res.status(404).json({ error: 'Employee not found' });
  const locationId = req.body.locationId || '';
  if (!inScope(req, emp.locationId || '') || (locationId && !inScope(req, locationId))) return res.status(403).json({ error: 'Permission denied' });
  if (locationId && !await db.collection('locations').findOne({ id: locationId })) return res.status(400).json({ error: 'Location not found' });
  await db.collection('employees').updateOne({ id: emp.id }, { $set: { locationId } });
  res.json({ success: true });
});

// employee edit: department, primary location, extra allowed locations
app.post('/api/employees/:id/update', requireStaff, async (req, res) => {
  const emp = await db.collection('employees').findOne({ id: req.params.id.toUpperCase() });
  if (!emp || emp.role === 'admin') return res.status(404).json({ error: 'Employee not found' });
  if (!scopeFilter({ ...req, query: {} })(emp)) return res.status(403).json({ error: 'Permission denied' });
  const set = {};
  const { out, err } = cleanEmpFields(req.body, req);
  if (err.length) return res.status(400).json({ error: err[0] });
  Object.assign(set, out);
  if (req.body.active !== undefined) set.active = !!req.body.active;
  if (req.body.department !== undefined) {
    set.department = cleanDept(req.body.department);
    if (req.deptScope && req.deptScope.length && !req.deptScope.includes(set.department)) return res.status(403).json({ error: 'You can only use your own department(s)' });
  }
  const all = await db.collection('locations').find({}).toArray();
  if (req.body.locationId !== undefined) {
    const lid = req.body.locationId || '';
    if (lid && (!all.some(l => l.id === lid) || !inScope(req, lid))) return res.status(403).json({ error: 'Invalid or not permitted location' });
    set.locationId = lid;
  }
  if (req.body.locationIds !== undefined) {
    const ids = [].concat(req.body.locationIds || []).filter(i => all.some(l => l.id === i) && inScope(req, i));
    const primary = set.locationId !== undefined ? set.locationId : emp.locationId;
    set.locationIds = [...new Set(ids)].filter(i => i !== primary);
  }
  if (Object.keys(set).length) {
    await db.collection('employees').updateOne({ id: emp.id }, { $set: set });
    const was = {}; Object.keys(set).forEach(k => { was[k] = k === 'monthlySalary' && !hasPerm(req, 'salary') ? undefined : emp[k]; });
    await audit(req, set.active === false && emp.active !== false ? 'employee.deactivate' : 'employee.update', emp.id, { before: was, after: set });
  }
  res.json({ success: true });
});
 
app.delete('/api/employees/:id', requireStaff, async (req, res) => {
  const { id } = req.params;
  const emp = await db.collection('employees').findOne({ id });
  if (emp && !inScope(req, emp.locationId || '')) return res.status(403).json({ error: 'Permission denied' });
  await db.collection('employees').deleteOne({ id });
  await db.collection('attendance').deleteMany({ empId: id });
  res.json({ success: true });
});
 
// ── STATUS CHECK ───────────────────────────────────────────
app.get('/api/status/:empId', async (req, res) => {
  const empId = req.params.empId.toUpperCase();
  const deviceId = getDeviceId(req);
  const emp = await db.collection('employees').findOne({ id: empId });
  if (!emp) return res.json({ status: 'not_registered' });
 
  if (emp.active === false) return res.json({ status: 'not_registered' });
  const record = await findActive(emp.id);
  if (!record) {
    const closed = await recentlyClosed(emp.id);
    if (closed) return res.json({ status: 'already_out', employee: publicEmp(emp), record: closed });
    return res.json({ status: 'punch_in', employee: publicEmp(emp) });
  }
 
  // If already checked in — check if this device did it
  if (record.checkOut) return res.json({ status: 'already_out', employee: publicEmp(emp), record });
 
  // Same device check for punch out
  if (record.deviceId && record.deviceId !== deviceId) {
    return res.json({ status: 'different_device', employee: publicEmp(emp), record });
  }
 
  res.json({ status: 'punch_out', employee: publicEmp(emp), record });
});
 
// Check if device already has active session
app.get('/api/device-session', async (req, res) => {
  const deviceId = getDeviceId(req);
  const record = await db.collection('attendance').findOne({ deviceId, date: { $gte: yesterday() }, checkOut: { $exists: false } });
  if (!record) return res.json({ hasSession: false });
  const emp = await db.collection('employees').findOne({ id: record.empId });
  res.json({ hasSession: true, empId: record.empId, empName: emp?.name || record.empName, record });
});
 
// ── ATTENDANCE ROUTES ──────────────────────────────────────
app.post('/api/attendance', async (req, res) => {
  const { empId, shift } = req.body;
  const deviceId = getDeviceId(req);
  if (!empId) return res.status(400).json({ error: 'EMP ID is required' });
 
  const emp = await db.collection('employees').findOne({ id: empId.toUpperCase() });
  if (!emp) return res.status(403).json({ error: 'not_listed', message: 'You are not registered.' });
  if (emp.active === false) return res.status(403).json({ error: 'not_listed', message: 'Your account is inactive. Please contact HR.' });
  const wl = await wrongLoc(emp, req.body);
  if (wl) return res.status(403).json(wl);
  const gIn = await geoGuard(emp, req.body);
  if (gIn) return res.status(403).json(gIn);
 
  // Check if this device already has an active session for someone else
  const deviceSession = await db.collection('attendance').findOne({ deviceId, date: { $gte: yesterday() }, checkOut: { $exists: false } });
  if (deviceSession && deviceSession.empId !== emp.id) {
    const prevEmp = await db.collection('employees').findOne({ id: deviceSession.empId });
    return res.status(409).json({
      error: 'device_busy',
      message: `Attendance is already in progress on this phone for ${prevEmp?.name || deviceSession.empId}. Please punch them out first.`
    });
  }
 
  const existing = (await findActive(emp.id)) || (await recentlyClosed(emp.id));
  if (existing) return res.status(409).json({ error: 'Today\'s attendance has already been marked!', employee: emp });
 
  const checkInTime = nowTime();
  const checkIn24 = convertTo24(checkInTime);
  const status = shift ? checkShiftStatus(shift, checkIn24) : 'present';
  const record = {
    id: Date.now().toString(), empId: emp.id, empName: emp.name,
    date: today(), time: checkInTime, shift: shift || 'G',
    status, deviceId, markedAt: new Date().toISOString(),
    locationId: scanLoc(emp, req.body) || undefined, locationName: (await locName(scanLoc(emp, req.body))) || undefined,
    department: emp.department || undefined
  };
  await db.collection('attendance').insertOne(record);
  res.json({ success: true, record, employee: publicEmp(emp) });
});
 
app.post('/api/checkout', async (req, res) => {
  const { empId } = req.body;
  const deviceId = getDeviceId(req);
  if (!empId) return res.status(400).json({ error: 'EMP ID is required' });
 
  const emp = await db.collection('employees').findOne({ id: empId.toUpperCase() });
  if (!emp) return res.status(403).json({ error: 'not_listed' });
  const wl = await wrongLoc(emp, req.body);
  if (wl) return res.status(403).json(wl);
  const gOut = await geoGuard(emp, req.body);
  if (gOut) return res.status(403).json(gOut);
 
  const record = await findActive(emp.id);
  if (!record) return res.status(404).json({ error: 'No check-in found for today. Please check in first.' });
  if (record.checkOut) return res.status(409).json({ error: 'already_out', message: 'You have already checked out!', record, employee: emp });
 
  // Device check — only same device can checkout
  if (record.deviceId && record.deviceId !== deviceId) {
    return res.status(403).json({ error: 'wrong_device', message: 'Punch out is only allowed from the same phone used to punch in!' });
  }
 
  const checkOut = nowTime();
  const totalHours = calcTotalHours(convertTo24(record.time), convertTo24(checkOut), record.date || today());
 
  await db.collection('attendance').updateOne(
    { id: record.id },
    { $set: { checkOut, checkOutAt: new Date().toISOString(), totalHours } }
  );
  const updated = await db.collection('attendance').findOne({ id: record.id });
  res.json({ success: true, record: updated, employee: emp });
});
 
// ── MANUAL ATTENDANCE ADD (PIN Protected) ─────────────────
app.post('/api/attendance/manual', requireStaff, async (req, res) => {
  const { pin, empId, date, shift, checkIn, checkOut, status, reason } = req.body;
  if (!hasPerm(req, 'editPunch')) return noPerm(res);
  if (!pinOk(req, pin)) return res.status(403).json({ error: 'Incorrect PIN!' });
  if (!needReason(reason)) return res.status(400).json({ error: 'Please enter a reason (at least 3 characters)' });
  if (!empId || !date || !checkIn) return res.status(400).json({ error: 'EMP ID, date and check-in are required' });
 
  const emp = await db.collection('employees').findOne({ id: empId.toUpperCase() });
  if (!emp) return res.status(404).json({ error: 'Employee not found: ' + empId });
  if (!scopeFilter({ ...req, query: {} })(emp)) return res.status(403).json({ error: 'This employee does not belong to your location' });
  if (await isLocked(emp.id, date)) return res.status(423).json({ error: 'This month is finalized for this employee. Ask IT to unlock it first.' });
 
  // Check if record already exists
  const existing = await db.collection('attendance').findOne({ empId: emp.id, date });
  if (existing) return res.status(409).json({ error: `Attendance for ${emp.name} on ${date} already exists! Please edit it instead.` });
 
  const checkIn24 = convertTo24(checkIn);
  const recordStatus = status || checkShiftStatus(shift || 'G', checkIn24);
  let totalHours = 'N/A';
  if (checkOut) totalHours = calcTotalHours(checkIn24, convertTo24(checkOut), date);
 
  const record = {
    id: Date.now().toString(), empId: emp.id, empName: emp.name,
    date, time: checkIn, shift: shift || 'G', status: recordStatus,
    checkOut: checkOut || null, totalHours,
    deviceId: 'manual', markedAt: new Date().toISOString(), manuallyAdded: true, addedBy: req.user.id,
    locationId: emp.locationId || undefined, locationName: (await locName(emp.locationId)) || undefined,
    department: emp.department || undefined
  };
  record.editReason = String(reason).trim();
  await db.collection('attendance').insertOne(record);
  await audit(req, 'attendance.add', emp.id, { date, checkIn, checkOut: checkOut || null, shift: shift || 'G' }, record.editReason);
  res.json({ success: true, record, employee: publicEmp(emp) });
});
 
// ── EDIT ATTENDANCE (PIN Protected) ───────────────────────
app.post('/api/attendance/edit', requireStaff, async (req, res) => {
  const { pin, attendanceId, checkIn, checkOut, shift, status, reason } = req.body;
  if (!hasPerm(req, 'editPunch')) return noPerm(res);
  if (!pinOk(req, pin)) return res.status(403).json({ error: 'Incorrect PIN!' });
  if (!needReason(reason)) return res.status(400).json({ error: 'Please enter a reason (at least 3 characters)' });
 
  const record = await db.collection('attendance').findOne({ id: attendanceId });
  if (!record) return res.status(404).json({ error: 'Record not found' });
  if (!scopeFilter({ ...req, query: {} })(record)) return res.status(403).json({ error: 'This record does not belong to your location' });
  if (await isLocked(record.empId, record.date)) return res.status(423).json({ error: 'This month is finalized for this employee. Ask IT to unlock it first.' });
 
  const updates = {};
  if (checkIn) {
    updates.time = checkIn;
    if (checkOut || record.checkOut) {
      updates.totalHours = calcTotalHours(convertTo24(checkIn), convertTo24(checkOut || record.checkOut), record.date);
    }
    if (shift || record.shift) {
      updates.status = checkShiftStatus(shift || record.shift, convertTo24(checkIn));
    }
  }
  if (checkOut) {
    updates.checkOut = checkOut;
    updates.totalHours = calcTotalHours(convertTo24(checkIn || record.time), convertTo24(checkOut), record.date);
  }
  if (shift) { updates.shift = shift; updates.status = checkShiftStatus(shift, convertTo24(checkIn || record.time)); }
  if (status) updates.status = status;
  updates.editedAt = new Date().toISOString(); updates.editedBy = req.user.id; updates.editReason = String(reason).trim();
 
  await audit(req, 'attendance.edit', record.empId, { date: record.date, before: { time: record.time, checkOut: record.checkOut || null, shift: record.shift, status: record.status }, after: updates }, updates.editReason);
  await db.collection('attendance').updateOne({ id: attendanceId }, { $set: updates });
  const updated = await db.collection('attendance').findOne({ id: attendanceId });
  res.json({ success: true, record: updated });
});
 
// Verify edit PIN
app.post('/api/verify-pin', requireStaff, async (req, res) => {
  const { pin } = req.body;
  if (!hasPerm(req, 'editPunch')) return noPerm(res);
  if (req.user.role === 'it') return res.json({ success: true, noPin: true });
  if (pin === EDIT_PIN) return res.json({ success: true });
  res.status(403).json({ error: 'Incorrect PIN' });
});
 
app.delete('/api/attendance/employee/:id', requireStaff, async (req, res) => {
  const { id } = req.params;
  const { date, reason } = req.query;
  if (!hasPerm(req, 'editPunch')) return noPerm(res);
  if (!needReason(reason)) return res.status(400).json({ error: 'Please enter a reason (at least 3 characters)' });
  const emp = await db.collection('employees').findOne({ id });
  if (emp && !scopeFilter({ ...req, query: {} })(emp)) return res.status(403).json({ error: 'Permission denied' });
  if (date && await isLocked(id, date)) return res.status(423).json({ error: 'This month is finalized for this employee. Ask IT to unlock it first.' });
  await audit(req, 'attendance.delete', id, { date: date || 'ALL' }, String(reason).trim());
  if (date) await db.collection('attendance').deleteMany({ empId: id, date });
  else await db.collection('attendance').deleteMany({ empId: id });
  res.json({ success: true });
});
 
app.get('/api/attendance/today', requireStaff, async (req, res) => {
  const emps = (await db.collection('employees').find({}).toArray()).filter(scopeFilter(req));
  const locs = await db.collection('locations').find({}).toArray();
  const todayAtt = await db.collection('attendance').find({ date: today() }).toArray();
  const result = emps.map(e => {
    const rec = todayAtt.find(a => a.empId === e.id);
    return { ...staffView(e, req), locationName: (locs.find(l => l.id === e.locationId) || {}).name || '', date: today(), time: rec ? rec.time : '—', checkOut: rec?.checkOut || '—', totalHours: rec?.totalHours || '—', shift: rec?.shift || '—', status: rec ? rec.status : 'absent', attended: !!rec };
  });
  res.json(result);
});
 
app.get('/api/attendance', requireStaff, async (req, res) => {
  const { date, empId } = req.query;
  const filter = {};
  if (date) filter.date = date;
  if (empId) filter.empId = empId;
  const result = (await db.collection('attendance').find(filter).sort({ markedAt: -1 }).toArray()).filter(scopeFilter(req));
  res.json(result);
});
 
app.get('/api/attendance/employee/:id', async (req, res) => {
  const emp = await db.collection('employees').findOne({ id: req.params.id.toUpperCase() });
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  const empAtt = await db.collection('attendance').find({ empId: emp.id }).sort({ markedAt: -1 }).toArray();
  const present = empAtt.filter(a => a.status === 'present').length;
  const late = empAtt.filter(a => a.status === 'late').length;
  res.json({ employee: publicEmp(emp), attendance: empAtt, stats: { present, late, total: empAtt.length } });
});
 
// Monthly attendance stats
app.get('/api/attendance/monthly', requireView, async (req, res) => {
  const { month, year } = req.query;
  const m = month || new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' }).slice(5,7);
  const y = year || new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' }).slice(0,4);
  const start = `${y}-${m}-01`;
  const end = `${y}-${m}-31`;
  const att = (await db.collection('attendance').find({ date: { $gte: start, $lte: end } }).toArray()).filter(scopeFilter(req));
  res.json(att);
});
 
// ── ADMIN LOGIN ────────────────────────────────────────────
const loginFails = new Map(); // best-effort throttle (per server instance)
app.post('/api/login', async (req, res) => {
  const { empId, password, role } = req.body;
  const id = String(empId || '').trim().toUpperCase();
  const key = (req.ip || '') + '|' + id;
  const f = loginFails.get(key);
  if (f && f.n >= 5 && Date.now() - f.t < 15 * 60 * 1000) return res.status(429).json({ error: 'Too many failed attempts. Please try again after 15 minutes.' });

  let user = null;
  if (role !== 'admin' && role !== 'manager') { // IT login
    const it = await db.collection('it_users').findOne({ id });
    if (it && checkPassword(password, it)) user = { id: it.id, name: it.name, role: 'it' };
  }
  if (role === 'manager') { // Site Manager login
    const m = await db.collection('managers').findOne({ id });
    if (m && checkPassword(password, m)) user = { id: m.id, name: m.name, role: 'manager' };
  }
  if (!user && role !== 'it' && role !== 'manager') { // Admin login (IT ne banaya hua admin ID)
    const ad = await db.collection('admins').findOne({ id });
    if (ad && checkPassword(password, ad)) user = { id: ad.id, name: ad.name, role: 'admin' };
    if (!user && !ad) { // purana super admin (employee + mobile)
      const emp = await db.collection('employees').findOne({ id, role: 'admin' });
      const expected = process.env.ADMIN_PASSWORD || emp?.mobile;
      if (emp && password && password === expected) user = { id: emp.id, name: emp.name, role: 'admin' };
    }
  }
  if (!user) {
    loginFails.set(key, { n: (f && Date.now() - f.t < 15 * 60 * 1000 ? f.n : 0) + 1, t: Date.now() });
    return res.status(401).json({ error: 'Incorrect ID or password' });
  }
  loginFails.delete(key);
  if (user.role === 'it') { // IT: seedha andar (poora access)
    setSession(res, req, user.id, 'it', '');
    return res.json({ success: true, admin: user });
  }
  if (user.role === 'manager') { // Site Manager: straight in, sees his states only
    setSession(res, req, user.id, 'manager', '');
    return res.json({ success: true, admin: user });
  }
  // Admin: pehle password, phir Project ID (ya ALL) — cookie tab tak "pending" rehti hai
  setSession(res, req, user.id, 'admin', '?');
  const b = await baseScope(user.id);
  res.json({ success: true, admin: user, needProject: true, projects: await adminProjects(b ? b.scope : []) });
});

// Admin step 2: ek Project ID chuno, ya ALL (apne sab projects)
app.post('/api/login/project', async (req, res) => {
  const ses = readSession(req);
  if (!ses || ses.role !== 'admin') return res.status(401).json({ error: 'Login required' });
  const b = await baseScope(ses.id);
  if (!b) return res.status(401).json({ error: 'Login required' });
  const want = String(req.body.projectId || '').trim().toUpperCase();
  if (!want) return res.status(400).json({ error: 'Enter a Project ID, or ALL' });
  const mine = await adminProjects(b.scope);
  let proj = 'ALL';
  if (want !== 'ALL') {
    const p = mine.find(x => x.id === want);
    if (!p) return res.status(403).json({ error: 'Project ID not found, or you do not have access to it' });
    proj = p.id;
  }
  setSession(res, req, ses.id, 'admin', proj);
  res.json({ success: true, project: proj, projectName: proj === 'ALL' ? 'All Projects' : mine.find(x => x.id === proj).name });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'mw_admin=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ success: true });
});
 
// ── IT USERS (sirf IT) ─────────────────────────────────────
const strip = ({ passHash, salt, _id, ...u }) => u;
const newId = p => p + Date.now().toString(36) + crypto.randomBytes(2).toString('hex');
async function idTaken(id) {
  return !!(await db.collection('employees').findOne({ id }) || await db.collection('it_users').findOne({ id }) || await db.collection('admins').findOne({ id }) || await db.collection('managers').findOne({ id }));
}
function checkNewLogin(b) {
  const id = String(b.id || '').trim().toUpperCase(), name = String(b.name || '').trim(), password = String(b.password || '');
  if (!/^[A-Z0-9_-]{3,20}$/.test(id)) return { error: 'ID must be 3-20 letters/numbers (e.g. AD001)' };
  if (!name) return { error: 'Name is required' };
  if (password.length < 6) return { error: 'Password must be at least 6 characters' };
  return { id, name, password };
}
app.get('/api/it-users', requireIT, async (req, res) => {
  const list = await db.collection('it_users').find({}).sort({ createdAt: 1 }).toArray();
  res.json(list.map(strip));
});
app.post('/api/it-users', requireIT, async (req, res) => {
  const v = checkNewLogin(req.body); if (v.error) return res.status(400).json(v);
  if (await idTaken(v.id)) return res.status(409).json({ error: 'This ID is already in use' });
  const salt = crypto.randomBytes(16).toString('hex');
  await db.collection('it_users').insertOne({ id: v.id, name: v.name, salt, passHash: hashPassword(v.password, salt), createdAt: new Date().toISOString() });
  res.json({ success: true });
});
app.post('/api/it-users/:id/password', requireIT, async (req, res) => {
  const password = String(req.body.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const id = req.params.id.toUpperCase();
  if (!await db.collection('it_users').findOne({ id })) return res.status(404).json({ error: 'IT user not found' });
  const salt = crypto.randomBytes(16).toString('hex');
  await db.collection('it_users').updateOne({ id }, { $set: { salt, passHash: hashPassword(password, salt) } });
  res.json({ success: true });
});
app.delete('/api/it-users/:id', requireIT, async (req, res) => {
  const id = req.params.id.toUpperCase();
  if (id === req.user.id) return res.status(400).json({ error: 'You cannot delete your own ID' });
  await db.collection('it_users').deleteOne({ id });
  res.json({ success: true });
});

// ── ADMIN IDs (IT banata hai) ──────────────────────────────
app.get('/api/admins', requireIT, async (req, res) => {
  const list = await db.collection('admins').find({}).sort({ createdAt: 1 }).toArray();
  res.json(list.map(strip));
});
const cleanDeptList = v => [...new Set((Array.isArray(v) ? v : String(v || '').split(',')).map(x => String(x).trim()).filter(Boolean))].slice(0, 30);
async function cleanLocs(b) {
  if (b.allLocations) return { allLocations: true, locations: [] };
  const ids = [].concat(b.locations || []).filter(Boolean);
  const all = await db.collection('locations').find({}).toArray();
  const ok = ids.filter(i => all.some(l => l.id === i));
  return { allLocations: false, locations: ok };
}
app.post('/api/admins', requireIT, async (req, res) => {
  const v = checkNewLogin(req.body); if (v.error) return res.status(400).json(v);
  if (await idTaken(v.id)) return res.status(409).json({ error: 'This ID is already in use' });
  const sc = { ...(await cleanLocs(req.body)), departments: cleanDeptList(req.body.departments), canSalary: req.body.canSalary !== false, canDocs: req.body.canDocs !== false, canEditPunch: req.body.canEditPunch !== false };
  if (!sc.allLocations && !sc.locations.length) return res.status(400).json({ error: 'Select at least one location (or All locations)' });
  const salt = crypto.randomBytes(16).toString('hex');
  await db.collection('admins').insertOne({ id: v.id, name: v.name, salt, passHash: hashPassword(v.password, salt), ...sc, createdBy: req.user.id, createdAt: new Date().toISOString() });
  res.json({ success: true });
});
app.post('/api/admins/:id/update', requireIT, async (req, res) => {
  const id = req.params.id.toUpperCase();
  const ad = await db.collection('admins').findOne({ id });
  if (!ad) return res.status(404).json({ error: 'Admin not found' });
  const set = {};
  if (req.body.name) set.name = String(req.body.name).trim();
  if (req.body.password) {
    if (String(req.body.password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    set.salt = crypto.randomBytes(16).toString('hex'); set.passHash = hashPassword(String(req.body.password), set.salt);
  }
  if (req.body.locations !== undefined || req.body.allLocations !== undefined) {
    const sc = await cleanLocs(req.body);
    if (!sc.allLocations && !sc.locations.length) return res.status(400).json({ error: 'Select at least one location' });
    Object.assign(set, sc);
  }
  if (req.body.departments !== undefined) set.departments = cleanDeptList(req.body.departments);
  ['canSalary', 'canDocs', 'canEditPunch'].forEach(k => { if (req.body[k] !== undefined) set[k] = !!req.body[k]; });
  if (Object.keys(set).length) await db.collection('admins').updateOne({ id }, { $set: set });
  res.json({ success: true });
});
app.delete('/api/admins/:id', requireIT, async (req, res) => {
  await db.collection('admins').deleteOne({ id: req.params.id.toUpperCase() });
  res.json({ success: true });
});

// ── ME / IT TOOLS ──────────────────────────────────────────
app.get('/api/me', requireView, async (req, res) => {
  const locs = await db.collection('locations').find({}).toArray();
  const mine = req.scope === '*' ? locs : locs.filter(l => req.scope.includes(l.id));
  res.json({ ...req.user, scope: req.scope, stateCodes: req.stateCodes || undefined, states: req.stateCodes ? req.stateCodes.map(c => (stateByCode(c) || { name: c }).name) : undefined, departments: req.deptScope || [], perms: req.perms || {}, locations: mine.map(l => ({ id: l.id, name: l.name })) });
});

app.get('/api/it/overview', requireIT, async (req, res) => {
  const t = today();
  const todayAtt = (await db.collection('attendance').find({ date: t }).toArray()).filter(scopeFilter(req));
  const open = todayAtt.filter(a => !a.checkOut).map(a => ({
    empId: a.empId, empName: a.empName, time: a.time, shift: a.shift, locationName: a.locationName || '', phoneLocked: !!a.deviceId && a.deviceId !== 'manual'
  }));
  const emps = (await db.collection('employees').find({ role: 'employee' }).toArray()).filter(scopeFilter(req));
  res.json({
    db: dbKind,
    employees: emps.length,
    todayPunches: todayAtt.length,
    open,
    ...(req.user.role === 'it' ? {
      admins: await db.collection('admins').countDocuments(),
      itUsers: await db.collection('it_users').countDocuments(),
      locations: await db.collection('locations').countDocuments()
    } : {})
  });
});

// phone kho gaya / badal gaya — us din ka phone-lock hata do taaki naye phone se Punch Out ho sake
app.post('/api/it/unlock-device', requireIT, async (req, res) => {
  const empId = String(req.body.empId || '').trim().toUpperCase();
  const rec = await db.collection('attendance').findOne({ empId, date: today() });
  if (!rec) return res.status(404).json({ error: 'No attendance found for this employee today' });
  if (!inScope(req, rec.locationId || '')) return res.status(403).json({ error: 'This employee does not belong to your location' });
  if (rec.checkOut) return res.status(409).json({ error: 'This employee has already punched out today' });
  await db.collection('attendance').updateOne({ id: rec.id }, { $set: { deviceId: '', unlockedBy: req.user.id, unlockedAt: new Date().toISOString() } });
  res.json({ success: true });
});

// ── EXCEL EXPORT ───────────────────────────────────────────
app.get('/api/export/today', requireStaff, async (req, res) => {
  const emps = (await db.collection('employees').find({}).toArray()).filter(scopeFilter(req));
  const locs = await db.collection('locations').find({}).toArray();
  const todayStr = today();
  const att = await db.collection('attendance').find({ date: todayStr }).toArray();
  const rows = [['EMP ID', 'Name', 'Mobile', 'Location', 'Department', 'Shift', 'Check-in', 'Check-out', 'Total Hours', 'Status']];
  emps.forEach(e => {
    const rec = att.find(a => a.empId === e.id);
    rows.push([e.id, e.name, staffView(e, req).mobile, (locs.find(l => l.id === e.locationId) || {}).name || '—', e.department || '—', rec?.shift || '—', rec?.time || '—', rec?.checkOut || '—', rec?.totalHours || '—', rec ? rec.status : 'Absent']);
  });
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [{wch:12},{wch:22},{wch:14},{wch:18},{wch:16},{wch:8},{wch:12},{wch:12},{wch:12},{wch:10}];
  XLSX.utils.book_append_sheet(wb, ws, "Today's Attendance");
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Disposition', `attachment; filename="Maswer_${todayStr}.xlsx"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});
 
app.get('/api/export/monthly', requireStaff, async (req, res) => {
  const { month, year } = req.query;
  const m = month || new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' }).slice(5,7);
  const y = year || new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' }).slice(0,4);
  const start = `${y}-${m}-01`;
  const end = `${y}-${m}-31`;
  const att = (await db.collection('attendance').find({ date: { $gte: start, $lte: end } }).sort({ date: 1, markedAt: 1 }).toArray()).filter(scopeFilter(req));
  const rows = [['EMP ID', 'Name', 'Location', 'Department', 'Date', 'Shift', 'Check-in', 'Check-out', 'Total Hours', 'Status']];
  att.forEach(a => rows.push([a.empId, a.empName, a.locationName||'—', a.department||'—', a.date, a.shift||'—', a.time, a.checkOut||'—', a.totalHours||'—', a.status]));
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [{wch:12},{wch:22},{wch:18},{wch:16},{wch:12},{wch:8},{wch:12},{wch:12},{wch:12},{wch:10}];
  XLSX.utils.book_append_sheet(wb, ws, `${y}-${m} Attendance`);
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Disposition', `attachment; filename="Maswer_${y}-${m}.xlsx"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});
 
app.get('/api/export/all', requireStaff, async (req, res) => {
  const att = (await db.collection('attendance').find({}).sort({ date: -1, markedAt: -1 }).toArray()).filter(scopeFilter(req));
  const rows = [['EMP ID', 'Name', 'Location', 'Department', 'Date', 'Shift', 'Check-in', 'Check-out', 'Total Hours', 'Status']];
  att.forEach(a => rows.push([a.empId, a.empName, a.locationName||'—', a.department||'—', a.date, a.shift||'—', a.time, a.checkOut||'—', a.totalHours||'—', a.status]));
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.aoa_to_sheet(rows);
  ws['!cols'] = [{wch:12},{wch:22},{wch:18},{wch:16},{wch:12},{wch:8},{wch:12},{wch:12},{wch:12},{wch:10}];
  XLSX.utils.book_append_sheet(wb, ws, 'Full Attendance');
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Disposition', `attachment; filename="Maswer_Full.xlsx"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});
 
// ── LOCATIONS / GEOFENCE (IT manage karta hai) ────────────
// public: scan page ko sirf yeh dikhana hai (naam + coordinates + radius)
app.get('/api/locations', async (req, res) => {
  const list = await db.collection('locations').find({}).sort({ createdAt: 1 }).toArray();
  res.json(list.map(l => ({ id: l.id, name: l.name, lat: l.lat, lng: l.lng, radius: l.radius, address: l.address || '', projectId: l.projectId || '', projectName: l.projectName || '' })));
});

// ── PROJECTS (IT): Project ID + naam, uske andar locations ──
async function projectVisible(req, p) {
  if (req.scope === '*' || p.createdBy === req.user.id) return true;
  return (await db.collection('locations').find({}).toArray()).some(l => l.projectId === p.id && req.scope.includes(l.id));
}
app.get('/api/projects', requireView, async (req, res) => {
  const list = await db.collection('projects').find({}).sort({ createdAt: 1 }).toArray();
  const locs = await db.collection('locations').find({}).toArray();
  const mine = req.scope === '*' ? list : list.filter(p => p.createdBy === req.user.id || locs.some(l => l.projectId === p.id && req.scope.includes(l.id)));
  res.json(mine.map(p => ({ ...strip(p), locations: locs.filter(l => l.projectId === p.id).length })));
});
async function stateFields(code) { const st = stateByCode(code); return st ? { stateCode: st.code, stateName: st.name } : { stateCode: '', stateName: '' }; }
app.post('/api/projects', requireStaff, async (req, res) => {
  const id = String(req.body.id || '').trim().toUpperCase(), name = String(req.body.name || '').trim();
  if (!/^[A-Z0-9_-]{2,20}$/.test(id)) return res.status(400).json({ error: 'Site Code must be 2-20 letters/numbers (e.g. PRJ-001)' });
  if (!name) return res.status(400).json({ error: 'Project name is required' });
  if (await db.collection('projects').findOne({ id })) return res.status(409).json({ error: 'This Project ID already exists' });
  await db.collection('projects').insertOne({ id, name, client: String(req.body.client || '').trim().slice(0, 80), ...(await stateFields(req.body.stateCode)), createdBy: req.user.id, createdAt: new Date().toISOString() });
  res.json({ success: true });
});
app.post('/api/projects/:id/update', requireStaff, async (req, res) => {
  const id = req.params.id.toUpperCase(), name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Project name is required' });
  const pr = await db.collection('projects').findOne({ id });
  if (!pr || !(await projectVisible(req, pr))) return res.status(404).json({ error: 'Project not found' });
  await db.collection('projects').updateOne({ id }, { $set: { name, client: req.body.client !== undefined ? String(req.body.client).trim().slice(0, 80) : (pr.client || ''), ...(req.body.stateCode !== undefined ? await stateFields(req.body.stateCode) : {}) } });
  for (const l of (await db.collection('locations').find({}).toArray()).filter(l => l.projectId === id)) await db.collection('locations').updateOne({ id: l.id }, { $set: { projectName: name } });
  res.json({ success: true });
});
app.delete('/api/projects/:id', requireStaff, async (req, res) => {
  const id = req.params.id.toUpperCase();
  const pr = await db.collection('projects').findOne({ id });
  if (!pr || !(await projectVisible(req, pr))) return res.status(404).json({ error: 'Project not found' });
  const n = (await db.collection('locations').find({}).toArray()).filter(l => l.projectId === id).length;
  if (n) return res.status(409).json({ error: `This project has ${n} location(s) — please remove them first.` });
  await db.collection('projects').deleteOne({ id });
  res.json({ success: true });
});

// har location ka apna QR (employee usi QR ko scan karke attendance lagata hai)
async function qrFor(req, loc) {
  const host = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
  const url = `${host}/scan?loc=${encodeURIComponent(loc.id)}`;
  return { url, qr: await QRCode.toDataURL(url, { width: 300, margin: 2, color: { dark: '#1E2D4E', light: '#FFFFFF' } }) };
}
app.get('/api/location-qrs', requireStaff, async (req, res) => {
  const locs = (await db.collection('locations').find({}).sort({ createdAt: 1 }).toArray()).filter(l => req.scope === '*' || req.scope.includes(l.id));
  const emps = await db.collection('employees').find({ role: 'employee' }).toArray();
  const out = [];
  for (const l of locs) out.push({ id: l.id, name: l.name, projectId: l.projectId || '', projectName: l.projectName || '', employees: emps.filter(e => e.locationId === l.id).length, ...(await qrFor(req, l)) });
  res.json(out);
});
function locBody(b) {
  const lat = parseFloat(b.lat), lng = parseFloat(b.lng), radius = parseInt(b.radius) || 100;
  const name = String(b.name || '').trim();
  if (!name) return { error: 'Location name is required' };
  if (!isFinite(lat) || !isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) return { error: 'Please enter a valid Lat/Lng' };
  if (radius < 10 || radius > 5000) return { error: 'Radius must be between 10 and 5000 meters' };
  return { name, lat, lng, radius, address: String(b.address || '').trim().slice(0, 200), projectId: String(b.projectId || '').toUpperCase(), _p: true };
}
async function withProject(v) {
  const p = await db.collection('projects').findOne({ id: v.projectId });
  if (!p) return { error: 'Please select (or create) a Project first' };
  const { _p, ...rest } = v;
  return { ...rest, projectName: p.name };
}
app.post('/api/locations', requireStaff, async (req, res) => {
  let v = locBody(req.body); if (v.error) return res.status(400).json(v);
  v = await withProject(v); if (v.error) return res.status(400).json(v);
  if (req.user.project && req.user.project !== 'ALL' && v.projectId !== req.user.project) return res.status(403).json({ error: 'You are logged in to project ' + req.user.project + '. Log in with ALL to add a location to another project.' });
  const loc = { id: newId('L'), ...v, createdBy: req.user.id, createdAt: new Date().toISOString() };
  await db.collection('locations').insertOne(loc);
  if (req.user.role === 'admin' && req.scope !== '*') { // HR can see the location they just created
    const ad = await db.collection('admins').findOne({ id: req.user.id });
    if (ad && !ad.allLocations) await db.collection('admins').updateOne({ id: ad.id }, { $set: { locations: [...(ad.locations || []), loc.id] } });
    req.scope.push(loc.id);
  }
  res.json({ success: true, location: loc, ...(await qrFor(req, loc)) });
});
app.post('/api/locations/:id/update', requireStaff, async (req, res) => {
  let v = locBody(req.body); if (v.error) return res.status(400).json(v);
  v = await withProject(v); if (v.error) return res.status(400).json(v);
  if (!await db.collection('locations').findOne({ id: req.params.id }) || !inScope(req, req.params.id)) return res.status(404).json({ error: 'Location not found' });
  await db.collection('locations').updateOne({ id: req.params.id }, { $set: { ...v, updatedAt: new Date().toISOString() } });
  res.json({ success: true });
});
app.delete('/api/locations/:id', requireStaff, async (req, res) => {
  const id = req.params.id;
  if (!inScope(req, id)) return res.status(404).json({ error: 'Location not found' });
  const used = (await db.collection('employees').find({}).toArray()).filter(e => e.locationId === id).length;
  if (used) return res.status(409).json({ error: `This location has ${used} employee(s) — please change their location first.` });
  await db.collection('locations').deleteOne({ id });
  for (const ad of await db.collection('admins').find({}).toArray()) {
    if ((ad.locations || []).includes(id)) await db.collection('admins').updateOne({ id: ad.id }, { $set: { locations: ad.locations.filter(x => x !== id) } });
  }
  res.json({ success: true });
});

// ── LOCATION BYPASS ───────────────────────────────────────
app.get('/api/location-bypass', requireIT, async (req, res) => {
  const bypass = await db.collection('settings').findOne({ key: 'location_bypass' });
  res.json(bypass ? bypass.value : []);
});
 
app.post('/api/location-bypass', requireIT, async (req, res) => {
  const { empId, pin } = req.body;
  if (!pinOk(req, pin)) return res.status(403).json({ error: 'Incorrect PIN!' });
  if (!empId) return res.status(400).json({ error: 'EMP ID is required' });
  const emp = await db.collection('employees').findOne({ id: empId.toUpperCase() });
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  if (!inScope(req, emp.locationId || '')) return res.status(403).json({ error: 'This employee does not belong to your location' });
  const bypass = await db.collection('settings').findOne({ key: 'location_bypass' });
  const list = bypass ? bypass.value : [];
  if (!list.find(e => e.id === emp.id)) {
    list.push({ id: emp.id, name: emp.name, addedAt: new Date().toISOString() });
    await db.collection('settings').updateOne({ key: 'location_bypass' }, { $set: { key: 'location_bypass', value: list } }, { upsert: true });
  }
  res.json({ success: true, list });
});
 
app.delete('/api/location-bypass/:empId', requireIT, async (req, res) => {
  const { pin } = req.body;
  if (!pinOk(req, pin)) return res.status(403).json({ error: 'Incorrect PIN!' });
  const bypass = await db.collection('settings').findOne({ key: 'location_bypass' });
  const list = bypass ? bypass.value.filter(e => e.id !== req.params.empId.toUpperCase()) : [];
  await db.collection('settings').updateOne({ key: 'location_bypass' }, { $set: { key: 'location_bypass', value: list } }, { upsert: true });
  res.json({ success: true, list });
});
 
// Check if employee is in bypass list
app.get('/api/location-bypass/check/:empId', async (req, res) => {
  const empId = req.params.empId.toUpperCase();
  const bypass = await db.collection('settings').findOne({ key: 'location_bypass' });
  const list = bypass ? bypass.value : [];
  const found = list.find(e => e.id === empId);
  res.json({ bypassed: !!found });
});
 
// Employee attendance summary (for scan page)
app.get('/api/attendance/summary/:empId', async (req, res) => {
  const empId = req.params.empId.toUpperCase();
  const emp = await db.collection('employees').findOne({ id: empId });
  if (!emp) return res.status(404).json({ error: 'Employee not found' });
  const att = await db.collection('attendance').find({ empId }).sort({ date: -1 }).limit(30).toArray();
  const present = att.filter(a => a.status === 'present').length;
  const late = att.filter(a => a.status === 'late').length;
  // Total hours calculation
  let totalMins = 0;
  att.forEach(a => {
    if (a.totalHours && a.totalHours !== 'N/A') {
      const match = a.totalHours.match(/(\d+)h\s*(\d+)m/);
      if (match) totalMins += parseInt(match[1])*60 + parseInt(match[2]);
    }
  });
  const avgHours = att.length ? `${Math.floor(totalMins/att.length/60)}h ${Math.floor((totalMins/att.length)%60)}m` : 'N/A';
  res.json({ employee: publicEmp(emp), totalDays: att.length, present, late, avgHours, recent: att.slice(0,7) });
});
 
// ── QR CODE ────────────────────────────────────────────────
app.get('/api/qr', requireStaff, async (req, res) => {
  const host = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
  const url = `${host}/scan`;
  try {
    const qrDataUrl = await QRCode.toDataURL(url, { width: 300, margin: 2, color: { dark: '#1E2D4E', light: '#FFFFFF' } });
    res.json({ qr: qrDataUrl, url });
  } catch(err) { res.status(500).json({ error: 'Failed to generate QR code' }); }
});
 
// ── HRMS: SALARY / PAYSLIPS / REPORTS / AUDIT ──────────────
const payroll = require('./payroll');
const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;
async function getSalarySettings() {
  const s = await db.collection('settings').findOne({ key: 'salary' });
  return payroll.settingsWith(s && s.value);
}
async function salaryEmp(req, id) {
  const e = await db.collection('employees').findOne({ id });
  if (!e || e.role === 'admin') return null;
  if (!scopeFilter({ ...req, query: {}, deptScope: req.deptScope })(e)) return null;
  return e;
}
async function calcFor(emp, month, S) {
  const [records, advances] = await Promise.all([
    db.collection('attendance').find({ empId: emp.id }).toArray(),
    db.collection('advances').find({ empId: emp.id, month }).toArray()
  ]);
  return payroll.calcMonth({ emp, records, settings: S, advances, month, today: today(), nowMs: Date.now() });
}
const slipId = (month, empId) => `PS-${month}-${empId}`;

app.get('/api/salary/settings', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  res.json(await getSalarySettings());
});
app.post('/api/salary/settings', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const b = req.body || {}, cur = await getSalarySettings(), n = { ...cur };
  const str = (k, max) => { if (b[k] !== undefined) n[k] = String(b[k]).slice(0, max); };
  str('companyName', 120); str('companyAddress', 300); str('currency', 8);
  if (b.logo !== undefined) {
    if (b.logo && (!/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(b.logo) || b.logo.length > 400000)) return res.status(400).json({ error: 'Logo must be a PNG or JPG under 300 KB' });
    n.logo = b.logo || '';
  }
  if (b.daysMode !== undefined) { if (!['calendar', 'fixed30'].includes(b.daysMode)) return res.status(400).json({ error: 'Invalid days mode' }); n.daysMode = b.daysMode; }
  const num = (k, min, max) => { if (b[k] !== undefined) { const v = Number(b[k]); if (!isFinite(v) || v < min || v > max) throw new Error(`Invalid ${k}`); n[k] = v; } };
  const bool = k => { if (b[k] !== undefined) n[k] = !!b[k]; };
  try {
    num('halfDayBelowHours', 0, 24); num('overtimeAfterHours', 0, 24); num('overtimeHourlyBasis', 1, 24); num('overtimeRate', 0, 5);
    num('lateFreePerMonth', 0, 31); num('lateDeductionDays', 0, 1);
  } catch (e) { return res.status(400).json({ error: e.message }); }
  ['weeklyOffPaid', 'overtimeEnabled', 'lateDeductionEnabled'].forEach(bool);
  if (b.weeklyOffDays !== undefined) n.weeklyOffDays = (Array.isArray(b.weeklyOffDays) ? b.weeklyOffDays : []).map(Number).filter(x => x >= 0 && x <= 6);
  if (b.holidays !== undefined) n.holidays = (Array.isArray(b.holidays) ? b.holidays : []).filter(h => h && /^\d{4}-\d{2}-\d{2}$/.test(h.date)).map(h => ({ date: h.date, name: String(h.name || 'Holiday').slice(0, 60) }));
  await db.collection('settings').updateOne({ key: 'salary' }, { $set: { key: 'salary', value: n } }, { upsert: true });
  await audit(req, 'settings.salary', 'salary', { daysMode: n.daysMode, halfDayBelowHours: n.halfDayBelowHours });
  res.json({ success: true, settings: payroll.settingsWith(n) });
});

// month summary — one row per employee (with a salary) in scope
app.get('/api/salary/month', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const month = String(req.query.month || today().slice(0, 7));
  if (!MONTH_RE.test(month)) return res.status(400).json({ error: 'Invalid month' });
  const S = await getSalarySettings();
  const emps = (await db.collection('employees').find({}).toArray()).filter(e => e.role !== 'admin' && Number(e.monthlySalary) > 0).filter(scopeFilter(req));
  const [att, adv, slips] = await Promise.all([
    db.collection('attendance').find({}).toArray(), db.collection('advances').find({ month }).toArray(), db.collection('payslips').find({ month }).toArray()
  ]);
  const rows = emps.map(e => {
    const c = payroll.calcMonth({ emp: e, records: att.filter(a => a.empId === e.id), settings: S, advances: adv.filter(a => a.empId === e.id), month, today: today(), nowMs: Date.now() });
    const s = slips.find(x => x.empId === e.id);
    return { empId: e.id, name: e.name, department: e.department || '', designation: e.designation || '', active: e.active !== false, monthly: c.monthly, perDay: c.perDay, counts: c.counts, earnedDays: c.earnedDays, overtime: c.overtime.pay, lateDeduction: c.late.deduction, advance: c.advance, net: c.net, hasIncomplete: c.hasIncomplete, monthOpen: c.monthOpen, slip: s ? { id: s.id, version: s.version, finalized: !!s.finalized } : null };
  });
  res.json({ month, settings: { daysMode: S.daysMode, halfDayBelowHours: S.halfDayBelowHours }, rows });
});
app.get('/api/salary/employee/:id', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const month = String(req.query.month || today().slice(0, 7));
  if (!MONTH_RE.test(month)) return res.status(400).json({ error: 'Invalid month' });
  const e = await salaryEmp(req, req.params.id);
  if (!e) return res.status(404).json({ error: 'Employee not found' });
  const S = await getSalarySettings();
  const calc = await calcFor(e, month, S);
  const advances = await db.collection('advances').find({ empId: e.id, month }).toArray();
  const slip = await db.collection('payslips').findOne({ id: slipId(month, e.id) });
  res.json({ employee: { id: e.id, name: e.name, designation: e.designation || '', department: e.department || '', joiningDate: e.joiningDate || '' }, calc, advances, slip: slip ? { id: slip.id, version: slip.version, finalized: !!slip.finalized, generatedAt: slip.generatedAt } : null });
});
app.post('/api/salary/advance', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const { empId, month, note } = req.body || {}, amount = Number((req.body || {}).amount);
  if (!MONTH_RE.test(String(month))) return res.status(400).json({ error: 'Invalid month' });
  if (!isFinite(amount) || amount <= 0 || amount > 10000000) return res.status(400).json({ error: 'Enter a valid amount' });
  const e = await salaryEmp(req, empId);
  if (!e) return res.status(404).json({ error: 'Employee not found' });
  if (await isLocked(e.id, month + '-01')) return res.status(423).json({ error: 'This month is finalized. Unlock it first.' });
  const a = { id: newId('V'), empId: e.id, month, amount, note: String(note || '').slice(0, 120), createdBy: req.user.id, createdAt: new Date().toISOString() };
  await db.collection('advances').insertOne(a);
  await audit(req, 'advance.add', e.id, { month, amount });
  res.json({ success: true, advance: a });
});
app.delete('/api/salary/advance/:id', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const a = await db.collection('advances').findOne({ id: req.params.id });
  if (!a) return res.status(404).json({ error: 'Not found' });
  const e = await salaryEmp(req, a.empId);
  if (!e) return res.status(404).json({ error: 'Not found' });
  if (await isLocked(a.empId, a.month + '-01')) return res.status(423).json({ error: 'This month is finalized. Unlock it first.' });
  await db.collection('advances').deleteOne({ id: a.id });
  await audit(req, 'advance.delete', a.empId, { month: a.month, amount: a.amount });
  res.json({ success: true });
});

// ── payslips ──
async function buildSnapshot(e, month, S) {
  const calc = await calcFor(e, month, S);
  return { company: { name: S.companyName, address: S.companyAddress, logo: S.logo, currency: S.currency },
    employee: { id: e.id, name: e.name, designation: e.designation || '', department: e.department || '', joiningDate: e.joiningDate || '', mobile: e.mobile || '' }, calc };
}
async function targetEmps(req, month, empId) {
  if (empId) { const e = await salaryEmp(req, empId); return e && Number(e.monthlySalary) > 0 ? [e] : []; }
  return (await db.collection('employees').find({}).toArray()).filter(e => e.role !== 'admin' && Number(e.monthlySalary) > 0 && e.active !== false).filter(scopeFilter({ ...req, query: {} }));
}
app.post('/api/payslips/generate', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const { month, empId } = req.body || {};
  if (!MONTH_RE.test(String(month))) return res.status(400).json({ error: 'Invalid month' });
  const S = await getSalarySettings(), emps = await targetEmps(req, month, empId);
  if (!emps.length) return res.status(404).json({ error: 'No employee with a salary found' });
  let made = 0, skipped = 0; const out = [];
  for (const e of emps) {
    const id = slipId(month, e.id), old = await db.collection('payslips').findOne({ id });
    if (old && old.finalized) { skipped++; continue; }
    const snap = await buildSnapshot(e, month, S), now = new Date().toISOString();
    const doc = { id, empId: e.id, month, version: (old ? old.version : 0) + 1, snapshot: snap, net: snap.calc.net, finalized: false, generatedAt: now, generatedBy: req.user.id };
    await db.collection('payslips').updateOne({ id }, { $set: doc }, { upsert: true });
    made++; out.push({ id, version: doc.version, net: doc.net });
  }
  await audit(req, 'payslip.generate', empId || 'ALL', { month, made, skipped });
  res.json({ success: true, made, skipped, slips: out });
});
app.post('/api/payslips/finalize', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const { month, empId } = req.body || {};
  if (!MONTH_RE.test(String(month))) return res.status(400).json({ error: 'Invalid month' });
  const S = await getSalarySettings(), emps = await targetEmps(req, month, empId);
  if (!emps.length) return res.status(404).json({ error: 'No employee with a salary found' });
  const blocked = []; const todo = [];
  for (const e of emps) {
    const id = slipId(month, e.id), old = await db.collection('payslips').findOne({ id });
    if (old && old.finalized) continue;
    const snap = await buildSnapshot(e, month, S);
    if (snap.calc.hasIncomplete) blocked.push({ empId: e.id, name: e.name, reason: 'Missed punch-out — fix the Incomplete day(s) first' });
    else if (snap.calc.monthOpen) blocked.push({ empId: e.id, name: e.name, reason: 'Month is not over yet' });
    else todo.push({ e, snap, old });
  }
  if (blocked.length && empId) return res.status(409).json({ error: blocked[0].reason, blocked });
  const now = new Date().toISOString();
  for (const { e, snap, old } of todo) {
    const id = slipId(month, e.id);
    await db.collection('payslips').updateOne({ id }, { $set: { id, empId: e.id, month, version: (old ? old.version : 0) + 1, snapshot: snap, net: snap.calc.net, finalized: true, finalizedAt: now, finalizedBy: req.user.id, generatedAt: now, generatedBy: req.user.id } }, { upsert: true });
  }
  await audit(req, 'payslip.finalize', empId || 'ALL', { month, finalized: todo.length, blocked: blocked.length });
  res.json({ success: true, finalized: todo.length, blocked });
});
app.post('/api/payslips/unlock', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const { month, empId, reason } = req.body || {};
  if (!MONTH_RE.test(String(month)) || !empId) return res.status(400).json({ error: 'Month and employee are required' });
  if (!needReason(reason)) return res.status(400).json({ error: 'A reason is required' });
  const id = slipId(month, empId), p = await db.collection('payslips').findOne({ id });
  if (!p || !p.finalized) return res.status(404).json({ error: 'This month is not finalized' });
  await db.collection('payslips').updateOne({ id }, { $set: { finalized: false } });
  await audit(req, 'payslip.unlock', empId, { month }, String(reason).trim());
  res.json({ success: true });
});
app.get('/api/payslips', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'salary')) return noPerm(res);
  const month = String(req.query.month || '');
  const q = MONTH_RE.test(month) ? { month } : (req.query.empId ? { empId: String(req.query.empId) } : {});
  const list = await db.collection('payslips').find(q).toArray();
  const out = [];
  for (const p of list) { const e = await db.collection('employees').findOne({ id: p.empId }); if (e && scopeFilter({ ...req, query: {} })(e)) out.push({ id: p.id, empId: p.empId, name: e.name, month: p.month, version: p.version, net: p.net, finalized: !!p.finalized, generatedAt: p.generatedAt }); }
  res.json(out);
});
async function slipForReq(req, res) {
  if (!hasPerm(req, 'salary')) { noPerm(res); return null; }
  const p = await db.collection('payslips').findOne({ id: req.params.id });
  const e = p && await salaryEmp(req, p.empId);
  if (!e) { res.status(404).json({ error: 'Payslip not found' }); return null; }
  return p;
}
app.get('/api/payslips/:id', requireStaff, async (req, res) => { const p = await slipForReq(req, res); if (p) res.json(p); });

// PDF
const PDFDocument = (() => { try { return require('pdfkit'); } catch (e) { return null; } })();
function payslipPdf(p) {
  return new Promise((resolve, reject) => {
    const s = p.snapshot, c = s.calc, cur = s.company.currency || 'Rs.';
    const money = n => `${cur} ${Number(n).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    const doc = new PDFDocument({ size: 'A4', margin: 40 }); const bufs = [];
    doc.on('data', d => bufs.push(d)); doc.on('end', () => resolve(Buffer.concat(bufs))); doc.on('error', reject);
    let y = 40;
    if (s.company.logo) { try { doc.image(Buffer.from(s.company.logo.split(',')[1], 'base64'), 40, y, { fit: [60, 50] }); } catch (e) {} }
    doc.font('Helvetica-Bold').fontSize(16).text(s.company.name || '', 110, y, { width: 445 });
    doc.font('Helvetica').fontSize(9).fillColor('#555').text(s.company.address || '', 110, doc.y, { width: 445 });
    doc.fillColor('#000'); y = 100;
    doc.font('Helvetica-Bold').fontSize(13).text(`PAYSLIP — ${c.month}`, 40, y); 
    doc.font('Helvetica').fontSize(9).text(`Payslip No: ${p.id}    Version: ${p.version}    Status: ${p.finalized ? 'FINAL' : 'DRAFT'}`, 40, y + 18);
    doc.moveTo(40, y + 34).lineTo(555, y + 34).stroke('#999');
    y += 44;
    const kv = (k, v, x, yy) => { doc.font('Helvetica').fontSize(9).fillColor('#666').text(k, x, yy); doc.font('Helvetica-Bold').fillColor('#000').text(String(v || '—'), x + 85, yy); };
    kv('Employee', s.employee.name, 40, y); kv('Employee ID', s.employee.id, 300, y);
    kv('Designation', s.employee.designation, 40, y + 15); kv('Department', s.employee.department, 300, y + 15);
    kv('Joining date', s.employee.joiningDate, 40, y + 30); kv('Monthly salary', money(c.monthly), 300, y + 30);
    y += 55;
    doc.font('Helvetica-Bold').fontSize(10).text('Attendance summary', 40, y); y += 15;
    doc.font('Helvetica').fontSize(9).text(`Present ${c.counts.present} · Half day ${c.counts.half} · Absent ${c.counts.absent} · Week off ${c.counts.off} · Holidays ${c.counts.holiday} · Paid days ${c.earnedDays} of ${c.basis} · Per day ${money(c.perDay)}`, 40, y, { width: 515 });
    y = doc.y + 12;
    const rowsE = [['Basic (earned days)', c.gross]]; if (c.overtime.pay) rowsE.push([`Overtime (${c.overtime.hours} h)`, c.overtime.pay]);
    const rowsD = []; if (c.late.deduction) rowsD.push([`Late deduction (${c.late.chargeable} late)`, c.late.deduction]); if (c.advance) rowsD.push(['Advance', c.advance]);
    doc.font('Helvetica-Bold').fontSize(10).text('Earnings', 40, y).text('Deductions', 300, y); y += 16;
    const n = Math.max(rowsE.length, rowsD.length, 1);
    for (let i = 0; i < n; i++) {
      doc.font('Helvetica').fontSize(9);
      if (rowsE[i]) { doc.text(rowsE[i][0], 40, y); doc.text(money(rowsE[i][1]), 170, y, { width: 100, align: 'right' }); }
      if (rowsD[i]) { doc.text(rowsD[i][0], 300, y); doc.text(money(rowsD[i][1]), 430, y, { width: 100, align: 'right' }); }
      y += 14;
    }
    doc.moveTo(40, y).lineTo(555, y).stroke('#999'); y += 6;
    doc.font('Helvetica-Bold').text('Total earnings', 40, y).text(money(c.earnings), 170, y, { width: 100, align: 'right' }).text('Total deductions', 300, y).text(money(c.deductions), 430, y, { width: 100, align: 'right' });
    y += 24; doc.fontSize(13).text(`Net pay: ${money(c.net)}`, 40, y);
    y += 30; doc.font('Helvetica-Bold').fontSize(9).text('Day-wise', 40, y); y += 13;
    const cols = [[40, 'Date'], [100, 'Day'], [140, 'Status'], [260, 'In'], [320, 'Out'], [380, 'Hours'], [430, 'Credit'], [480, 'Running']];
    const head = () => { doc.font('Helvetica-Bold').fontSize(8); cols.forEach(([x, t]) => doc.text(t, x, y)); y += 11; doc.font('Helvetica').fontSize(8); };
    head();
    const DN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    c.days.forEach(d => {
      if (y > 780) { doc.addPage(); y = 40; head(); }
      const v = [d.date, DN[d.dow], d.label, d.in || '', d.out || '', d.hours == null ? '' : payroll.hm(d.hours), d.credit == null ? '' : d.credit, d.status === 'future' || d.status === 'prejoin' ? '' : d.running.toFixed(2)];
      cols.forEach(([x], i) => doc.text(String(v[i]), x, y, { width: i === 2 ? 115 : 60, lineBreak: false })); y += 11;
    });
    doc.fontSize(7).fillColor('#777').text('This is a computer-generated payslip.', 40, Math.min(y + 14, 810));
    doc.end();
  });
}
app.get('/api/payslips/:id/pdf', requireStaff, async (req, res) => {
  const p = await slipForReq(req, res); if (!p) return;
  if (!PDFDocument) return res.status(501).json({ error: 'PDF library not installed (npm install pdfkit)' });
  const buf = await payslipPdf(p);
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${p.id}.pdf"`);
  res.send(buf);
});
// share link: signed, valid 7 days, no login needed
app.post('/api/payslips/:id/share', requireStaff, async (req, res) => {
  const p = await slipForReq(req, res); if (!p) return;
  const exp = Date.now() + 7 * 24 * 3600 * 1000, pl = `${p.id}|${exp}`;
  const token = Buffer.from(pl).toString('base64url') + '.' + sign('share|' + pl);
  const e = await db.collection('employees').findOne({ id: p.empId });
  const base = `${req.protocol}://${req.get('host')}`;
  const url = `${base}/api/p/${token}`;
  const phone = String((e && e.mobile) || '').replace(/\D/g, '');
  const text = `Your payslip for ${p.month}: ${url}`;
  await audit(req, 'payslip.share', p.empId, { month: p.month });
  res.json({ url, expires: new Date(exp).toISOString(), whatsapp: `https://wa.me/${phone.length === 10 ? '91' + phone : phone}?text=${encodeURIComponent(text)}`, mailto: `mailto:?subject=${encodeURIComponent('Payslip ' + p.month)}&body=${encodeURIComponent(text)}` });
});
app.get('/api/p/:token', async (req, res) => {
  try {
    const [b, sig] = String(req.params.token).split('.'); const pl = Buffer.from(b, 'base64url').toString();
    const good = Buffer.from(sign('share|' + pl)), got = Buffer.from(sig || '');
    if (good.length !== got.length || !crypto.timingSafeEqual(good, got)) return res.status(403).send('Invalid link');
    const [id, exp] = pl.split('|'); if (Date.now() > Number(exp)) return res.status(410).send('This link has expired');
    const p = await db.collection('payslips').findOne({ id });
    if (!p || !PDFDocument) return res.status(404).send('Not found');
    res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `inline; filename="${p.id}.pdf"`);
    res.send(await payslipPdf(p));
  } catch (e) { res.status(400).send('Invalid link'); }
});

// missed punch-out report: open punches older than the night-shift window
app.get('/api/reports/missed', requireStaff, async (req, res) => {
  const emps = (await db.collection('employees').find({}).toArray()).filter(scopeFilter(req));
  const ids = new Map(emps.map(e => [e.id, e]));
  const recs = await db.collection('attendance').find({ checkOut: { $exists: false } }).toArray();
  const td = today();
  const out = recs.filter(r => ids.has(r.empId) && r.date < td && (!r.markedAt || Date.now() - new Date(r.markedAt).getTime() > OPEN_MAX_HOURS * 3600 * 1000))
    .map(r => ({ empId: r.empId, name: ids.get(r.empId).name, department: ids.get(r.empId).department || '', date: r.date, checkIn: r.time, shift: r.shift || '', locked: false }))
    .sort((a, b) => b.date.localeCompare(a.date));
  res.json(out);
});
app.get('/api/audit', requireIT, async (req, res) => {
  const lim = Math.min(Number(req.query.limit) || 200, 1000);
  const list = await db.collection('audit_log').find({}).toArray();
  list.sort((a, b) => String(b.at).localeCompare(String(a.at)));
  res.json(list.slice(0, lim));
});
// ── HRMS END ───────────────────────────────────────────────

// ── DOCUMENTS (private storage) ────────────────────────────
const DOC_TYPES = ['aadhaar', 'pan', 'photo', 'bank', 'offer', 'appointment', 'experience', 'relieving', 'other'];
const DOC_MIME = { 'application/pdf': 'pdf', 'image/jpeg': 'jpg', 'image/png': 'png' };
const DOC_MAX = 5 * 1024 * 1024;
const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, ''), SB_KEY = process.env.SUPABASE_SERVICE_KEY || '', SB_BUCKET = process.env.SUPABASE_BUCKET || 'hr-documents';
const useSB = !!(SB_URL && SB_KEY);
const UP_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'data', 'uploads');
const sbH = extra => ({ Authorization: 'Bearer ' + SB_KEY, apikey: SB_KEY, ...(extra || {}) });
let bucketReady = false;
async function ensureBucket() {
  if (bucketReady) return;
  await fetch(`${SB_URL}/storage/v1/bucket`, { method: 'POST', headers: sbH({ 'Content-Type': 'application/json' }), body: JSON.stringify({ id: SB_BUCKET, name: SB_BUCKET, public: false, file_size_limit: DOC_MAX, allowed_mime_types: Object.keys(DOC_MIME) }) }).catch(() => {});
  bucketReady = true;
}
function magicOk(buf, mime) {
  if (mime === 'application/pdf') return buf.slice(0, 4).toString() === '%PDF';
  if (mime === 'image/png') return buf.slice(0, 4).toString('hex') === '89504e47';
  if (mime === 'image/jpeg') return buf.slice(0, 3).toString('hex') === 'ffd8ff';
  return false;
}
async function docEmp(req, res, empId) {
  const e = await db.collection('employees').findOne({ id: empId });
  if (!e || e.role === 'admin' || !scopeFilter({ ...req, query: {} })(e)) { res.status(404).json({ error: 'Employee not found' }); return null; }
  return e;
}
const docView = d => ({ id: d.id, empId: d.empId, type: d.type, label: d.label, fileName: d.fileName, mime: d.mime, size: d.size, uploadedAt: d.uploadedAt, uploadedBy: d.uploadedBy });
const canDoc = (req, type) => hasPerm(req, 'docs') || type === 'photo';
async function removeFile(d) {
  try {
    if (useSB) await fetch(`${SB_URL}/storage/v1/object/${SB_BUCKET}/${d.path}`, { method: 'DELETE', headers: sbH() });
    else fs.unlinkSync(path.join(UP_DIR, d.path));
  } catch (e) { /* already gone */ }
}
// all documents of every employee in scope (Employee Documents screen)
app.get('/api/documents', requireStaff, async (req, res) => {
  if (!hasPerm(req, 'docs')) return noPerm(res);
  const emps = (await db.collection('employees').find({}).toArray()).filter(e => e.role !== 'admin' && scopeFilter({ ...req, query: {} })(e));
  const ok = new Set(emps.map(e => e.id));
  const list = (await db.collection('documents').find({ status: 'ok' }).toArray()).filter(d => ok.has(d.empId));
  res.json(list.map(docView));
});
app.get('/api/employees/:id/documents', requireStaff, async (req, res) => {
  const e = await docEmp(req, res, req.params.id); if (!e) return;
  const list = (await db.collection('documents').find({ empId: e.id, status: 'ok' }).toArray()).filter(d => canDoc(req, d.type));
  res.json(list.map(docView));
});
// step 1: validate + get an upload target
app.post('/api/employees/:id/documents/init', requireStaff, async (req, res) => {
  const b = req.body || {}, type = String(b.type || '');
  if (!DOC_TYPES.includes(type)) return res.status(400).json({ error: 'Invalid document type' });
  if (!canDoc(req, type)) return noPerm(res);
  const e = await docEmp(req, res, req.params.id); if (!e) return;
  const mime = String(b.mime || ''), size = Number(b.size);
  if (!DOC_MIME[mime]) return res.status(400).json({ error: 'Only PDF, JPG or PNG files are allowed' });
  if (!isFinite(size) || size <= 0 || size > DOC_MAX) return res.status(400).json({ error: 'File must be 5 MB or smaller' });
  let replaceOf = null;
  if (b.replaceOf) { replaceOf = await db.collection('documents').findOne({ id: String(b.replaceOf), empId: e.id }); if (!replaceOf) return res.status(404).json({ error: 'Document to replace not found' }); }
  const id = newId('D'), p = `${e.id}/${id}.${DOC_MIME[mime]}`, label = String(b.label || '').replace(/[<>]/g, '').trim().slice(0, 40) || undefined;
  const doc = { id, empId: e.id, type, label, fileName: String(b.fileName || 'file').replace(/[^\w.\- ]/g, '_').slice(0, 80), mime, size, path: p, status: 'pending', replaceOf: replaceOf ? replaceOf.id : undefined, uploadedBy: req.user.id, uploadedAt: new Date().toISOString() };
  await db.collection('documents').insertOne(doc);
  if (useSB) {
    await ensureBucket();
    const r = await fetch(`${SB_URL}/storage/v1/object/upload/sign/${SB_BUCKET}/${p}`, { method: 'POST', headers: sbH({ 'Content-Type': 'application/json' }), body: '{}' });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.url) return res.status(502).json({ error: 'Storage error: ' + (j.message || j.error || r.status) });
    return res.json({ docId: id, mode: 'supabase', uploadUrl: SB_URL + '/storage/v1' + j.url, method: 'PUT', fieldName: 'file' });
  }
  res.json({ docId: id, mode: 'local', uploadUrl: `/api/documents/${id}/upload`, method: 'PUT' });
});
// local storage only: raw upload (small files; production uses signed Supabase upload)
app.put('/api/documents/:id/upload', requireStaff, express.raw({ type: () => true, limit: '5mb' }), async (req, res) => {
  const d = await db.collection('documents').findOne({ id: req.params.id });
  if (!d || d.status !== 'pending' || d.uploadedBy !== req.user.id) return res.status(404).json({ error: 'Upload not found' });
  if (useSB) return res.status(400).json({ error: 'Use the storage upload URL' });
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || !buf.length || buf.length > DOC_MAX) return res.status(400).json({ error: 'File must be 5 MB or smaller' });
  if (!magicOk(buf, d.mime)) return res.status(400).json({ error: 'File content does not match its type' });
  fs.mkdirSync(path.dirname(path.join(UP_DIR, d.path)), { recursive: true });
  fs.writeFileSync(path.join(UP_DIR, d.path), buf);
  await db.collection('documents').updateOne({ id: d.id }, { $set: { size: buf.length } });
  res.json({ success: true });
});
// step 3: confirm → live (replaces the old one if any)
app.post('/api/documents/:id/complete', requireStaff, async (req, res) => {
  const d = await db.collection('documents').findOne({ id: req.params.id });
  if (!d || d.status !== 'pending' || d.uploadedBy !== req.user.id) return res.status(404).json({ error: 'Upload not found' });
  if (!canDoc(req, d.type)) return noPerm(res);
  const e = await docEmp(req, res, d.empId); if (!e) return;
  if (useSB) {
    const r = await fetch(`${SB_URL}/storage/v1/object/info/${SB_BUCKET}/${d.path}`, { headers: sbH() });
    if (!r.ok) return res.status(400).json({ error: 'File was not uploaded' });
  } else if (!fs.existsSync(path.join(UP_DIR, d.path))) return res.status(400).json({ error: 'File was not uploaded' });
  if (d.replaceOf) { const old = await db.collection('documents').findOne({ id: d.replaceOf }); if (old) { await removeFile(old); await db.collection('documents').deleteOne({ id: old.id }); } }
  else if (d.type !== 'other') { // one per type
    const olds = await db.collection('documents').find({ empId: d.empId, type: d.type, status: 'ok' }).toArray();
    for (const o of olds) { await removeFile(o); await db.collection('documents').deleteOne({ id: o.id }); }
  }
  await db.collection('documents').updateOne({ id: d.id }, { $set: { status: 'ok', replacedAt: d.replaceOf ? new Date().toISOString() : undefined } });
  if (d.type === 'photo') await db.collection('employees').updateOne({ id: d.empId }, { $set: { photoDocId: d.id } });
  await audit(req, d.replaceOf ? 'document.replace' : 'document.upload', d.empId, { type: d.type, file: d.fileName });
  res.json({ success: true, document: docView({ ...d, status: 'ok' }) });
});
app.get('/api/documents/:id/file', requireStaff, async (req, res) => {
  const d = await db.collection('documents').findOne({ id: req.params.id });
  if (!d || d.status !== 'ok' || !canDoc(req, d.type)) return res.status(404).json({ error: 'Document not found' });
  const e = await docEmp(req, res, d.empId); if (!e) return;
  res.setHeader('Content-Type', d.mime);
  res.setHeader('Content-Disposition', `${req.query.download ? 'attachment' : 'inline'}; filename="${d.fileName.replace(/"/g, '')}"`);
  res.setHeader('Cache-Control', 'private, no-store');
  if (useSB) {
    const r = await fetch(`${SB_URL}/storage/v1/object/${SB_BUCKET}/${d.path}`, { headers: sbH() });
    if (!r.ok) return res.status(404).json({ error: 'File missing in storage' });
    return res.send(Buffer.from(await r.arrayBuffer()));
  }
  const fp = path.join(UP_DIR, d.path);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File missing' });
  res.send(fs.readFileSync(fp));
});
app.delete('/api/documents/:id', requireStaff, async (req, res) => {
  const d = await db.collection('documents').findOne({ id: req.params.id });
  if (!d || !canDoc(req, d.type)) return res.status(404).json({ error: 'Document not found' });
  const e = await docEmp(req, res, d.empId); if (!e) return;
  await removeFile(d); await db.collection('documents').deleteOne({ id: d.id });
  if (d.type === 'photo' && e.photoDocId === d.id) await db.collection('employees').updateOne({ id: e.id }, { $set: { photoDocId: '' } });
  await audit(req, 'document.delete', d.empId, { type: d.type, file: d.fileName });
  res.json({ success: true });
});
// ── DOCUMENTS END ──────────────────────────────────────────

// ── SITE WATCH: who is working where, right now ────────────
app.get('/api/sitewatch', requireView, async (req, res) => {
  const siteOk = scopeFilter({ ...req, query: { location: req.query.location }, deptScope: [] });
  const empOk = scopeFilter(req);
  const locs = (await db.collection('locations').find({}).sort({ createdAt: 1 }).toArray()).filter(l => siteOk({ locationId: l.id }));
  const emps = (await db.collection('employees').find({}).toArray()).filter(e => e.role !== 'admin' && e.active !== false).filter(empOk);
  const td = today(), yd = yesterday();
  const att = (await db.collection('attendance').find({}).toArray()).filter(a => a.date === td || (a.date === yd && !a.checkOut && a.markedAt && Date.now() - new Date(a.markedAt).getTime() < OPEN_MAX_HOURS * 3600 * 1000));
  const rec = {}; att.forEach(a => { if (!rec[a.empId] || a.date === td) rec[a.empId] = a; });
  const mk = (e, r) => ({ id: e.id, name: e.name, department: e.department || '', designation: e.designation || '', photoDocId: e.photoDocId || '',
    status: !r ? 'absent' : (r.checkOut ? 'left' : 'inside'), late: !!(r && r.status === 'late'), in: r ? r.time : '', out: r && r.checkOut ? r.checkOut : '',
    since: r && !r.checkOut && r.markedAt ? Math.max(0, Math.floor((Date.now() - new Date(r.markedAt).getTime()) / 60000)) : null, home: e.locationId || '' });
  const siteOf = e => { const r = rec[e.id]; return (r && r.locationId) || e.locationId || ''; };
  const sites = locs.map(l => {
    const people = emps.filter(e => siteOf(e) === l.id).map(e => mk(e, rec[e.id]));
    const c = s => people.filter(p => p.status === s).length;
    return { id: l.id, name: l.name, projectId: l.projectId || '', projectName: l.projectName || '', assigned: emps.filter(e => e.locationId === l.id).length, inside: c('inside'), left: c('left'), absent: c('absent'), late: people.filter(p => p.late).length, people };
  });
  const known = new Set(locs.map(l => l.id));
  const stray = emps.filter(e => !known.has(siteOf(e)) && !(req.query.location && req.query.location !== 'all'));
  if (stray.length) { const people = stray.map(e => mk(e, rec[e.id])); const c = s => people.filter(p => p.status === s).length;
    sites.push({ id: '', name: 'No site assigned', projectId: '', projectName: '', assigned: people.length, inside: c('inside'), left: c('left'), absent: c('absent'), late: people.filter(p => p.late).length, people }); }
  const sum = k => sites.reduce((a, s) => a + s[k], 0);
  res.json({ at: new Date().toISOString(), totals: { sites: locs.length, staff: emps.length, inside: sum('inside'), left: sum('left'), absent: sum('absent'), late: sum('late') }, sites });
});
// ── SITE WATCH END ─────────────────────────────────────────

// ── ATTENDANCE LEDGER (project-wise view + Excel) ──────────
async function ledgerRows(req) {
  const [att, locs, emps] = await Promise.all([db.collection('attendance').find(req.query.date && req.query.date !== 'all' ? { date: String(req.query.date) } : {}).toArray(), db.collection('locations').find({}).toArray(), db.collection('employees').find({}).toArray()]);
  const ok = scopeFilter({ ...req, query: { location: req.query.location, department: req.query.department } });
  const L = Object.fromEntries(locs.map(l => [l.id, l])), E = Object.fromEntries(emps.map(e => [e.id, e]));
  const out = att.filter(ok).map(a => {
    const e = E[a.empId] || {}, l = L[a.locationId || e.locationId] || {};
    return { id: a.id, empId: a.empId, empName: a.empName || e.name || '', date: a.date, time: a.time || '', checkOut: a.checkOut || '', totalHours: a.totalHours || '', status: a.status || '', shift: a.shift || '',
      locationId: l.id || '', locationName: a.locationName || l.name || '', projectId: l.projectId || '', projectName: l.projectName || '', department: a.department || e.department || '' };
  });
  out.sort((x, y) => String(y.date).localeCompare(String(x.date)) || String(x.empName).localeCompare(String(y.empName)));
  return out;
}
app.get('/api/attendance/ledger', requireView, async (req, res) => { res.json(await ledgerRows(req)); });
const LEDGER_HEAD = ['Employee Name', 'EMP ID', 'Project', 'Location', 'Department', 'Date', 'In Time', 'Out Time', 'Total Working Hours', 'Status'];
const ledgerLine = r => [r.empName, r.empId, r.projectName || '—', r.locationName || '—', r.department || '—', r.date, r.time || '—', r.checkOut || '—', r.totalHours || '—', r.status];
app.get('/api/export/attendance', requireView, async (req, res) => {
  const proj = String(req.query.project || 'all'), rows = await ledgerRows(req);
  const wb = XLSX.utils.book_new();
  const addSheet = (name, list) => {
    const ws = XLSX.utils.aoa_to_sheet([LEDGER_HEAD, ...list.map(ledgerLine)]);
    ws['!cols'] = [{ wch: 24 }, { wch: 12 }, { wch: 22 }, { wch: 22 }, { wch: 16 }, { wch: 12 }, { wch: 11 }, { wch: 11 }, { wch: 18 }, { wch: 10 }];
    XLSX.utils.book_append_sheet(wb, ws, (String(name).replace(/[\\\/?*\[\]:]/g, ' ').trim() || 'Sheet').slice(0, 31));
  };
  if (proj === 'all') {
    addSheet('All Projects', rows);
    const names = [...new Set(rows.map(r => r.projectName || 'No project'))];
    names.forEach(n => addSheet(n, rows.filter(r => (r.projectName || 'No project') === n)));
  } else addSheet(rows.find(r => r.projectId === proj)?.projectName || proj, rows.filter(r => r.projectId === proj));
  const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
  res.setHeader('Content-Disposition', `attachment; filename="Attendance_${proj === 'all' ? 'All_Projects' : proj}_${req.query.date && req.query.date !== 'all' ? req.query.date : 'All_Dates'}.xlsx"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});
// ── ATTENDANCE LEDGER END ──────────────────────────────────

// ── STATES & SITE MANAGERS ─────────────────────────────────
const STATES = [['Gujarat', '8101'], ['Rajasthan', '8102'], ['Maharashtra', '8103'], ['Madhya Pradesh', '8104'], ['Uttar Pradesh', '8105'], ['Haryana', '8106'], ['Punjab', '8107'], ['Himachal Pradesh', '8108'], ['Uttarakhand', '8109'], ['Bihar', '8110'], ['Jharkhand', '8111'], ['West Bengal', '8112'], ['Odisha', '8113'], ['Chhattisgarh', '8114'], ['Karnataka', '8115'], ['Tamil Nadu', '8116'], ['Kerala', '8117'], ['Andhra Pradesh', '8118'], ['Telangana', '8119'], ['Goa', '8120'], ['Assam', '8121'], ['Meghalaya', '8122'], ['Manipur', '8123'], ['Mizoram', '8124'], ['Nagaland', '8125'], ['Tripura', '8126'], ['Arunachal Pradesh', '8127'], ['Sikkim', '8128']].map(([name, code]) => ({ name, code }));
const stateByCode = c => STATES.find(s => s.code === String(c || '').trim());
app.get('/api/states', requireView, async (req, res) => {
  const ps = await db.collection('projects').find({}).toArray();
  res.json(STATES.map(s => ({ ...s, projects: ps.filter(p => p.stateCode === s.code).length })));
});
function cleanCodes(v) {
  const arr = Array.isArray(v) ? v : String(v || '').split(/[,\s]+/);
  const codes = [...new Set(arr.map(x => String(x).trim()).filter(Boolean))];
  const bad = codes.filter(c => !stateByCode(c));
  return { codes, bad };
}
const mgrView = m => ({ id: m.id, name: m.name, stateCodes: m.stateCodes || [], states: (m.stateCodes || []).map(c => (stateByCode(c) || { name: c }).name), createdAt: m.createdAt });
app.get('/api/managers', requireStaff, async (req, res) => {
  res.json((await db.collection('managers').find({}).sort({ createdAt: 1 }).toArray()).map(mgrView));
});
app.post('/api/managers', requireStaff, async (req, res) => {
  const v = checkNewLogin(req.body); if (v.error) return res.status(400).json(v);
  if (await idTaken(v.id)) return res.status(409).json({ error: 'This ID is already in use' });
  const c = cleanCodes(req.body.stateCodes);
  if (c.bad.length) return res.status(400).json({ error: 'Unknown state code: ' + c.bad.join(', ') });
  if (!c.codes.length) return res.status(400).json({ error: 'Enter at least one state code (e.g. 8101)' });
  const salt = crypto.randomBytes(16).toString('hex');
  await db.collection('managers').insertOne({ id: v.id, name: v.name, salt, passHash: hashPassword(v.password, salt), stateCodes: c.codes, createdBy: req.user.id, createdAt: new Date().toISOString() });
  await audit(req, 'manager.create', v.id, { stateCodes: c.codes });
  res.json({ success: true });
});
app.post('/api/managers/:id/update', requireStaff, async (req, res) => {
  const m = await db.collection('managers').findOne({ id: req.params.id });
  if (!m) return res.status(404).json({ error: 'Site manager not found' });
  const set = {};
  if (req.body.name !== undefined) { const n = String(req.body.name).trim(); if (!n) return res.status(400).json({ error: 'Name is required' }); set.name = n; }
  if (req.body.stateCodes !== undefined) {
    const c = cleanCodes(req.body.stateCodes);
    if (c.bad.length) return res.status(400).json({ error: 'Unknown state code: ' + c.bad.join(', ') });
    if (!c.codes.length) return res.status(400).json({ error: 'Enter at least one state code (e.g. 8101)' });
    set.stateCodes = c.codes;
  }
  if (req.body.password) {
    if (String(req.body.password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const salt = crypto.randomBytes(16).toString('hex'); set.salt = salt; set.passHash = hashPassword(String(req.body.password), salt);
  }
  await db.collection('managers').updateOne({ id: m.id }, { $set: set });
  await audit(req, 'manager.update', m.id, { stateCodes: set.stateCodes, passwordChanged: !!req.body.password });
  res.json({ success: true });
});
app.delete('/api/managers/:id', requireStaff, async (req, res) => {
  await db.collection('managers').deleteOne({ id: req.params.id });
  await audit(req, 'manager.delete', req.params.id);
  res.json({ success: true });
});
// ── STATES & SITE MANAGERS END ─────────────────────────────

// ── PAGE ROUTES ────────────────────────────────────────────
const PUB = (process.env.PUBLIC_DIR || (fs.existsSync(path.join(__dirname,'public')) ? path.join(__dirname,'public') : __dirname));
app.get('/', (req, res) => res.sendFile(path.join(PUB, 'index.html')));
app.get('/scan', (req, res) => res.sendFile(path.join(PUB, 'scan.html')));
app.get('/attendance', (req, res) => res.sendFile(path.join(PUB, 'attendance.html')));
 
// ── START ──────────────────────────────────────────────────
module.exports = app;
if (require.main === module || process.env.START_SERVER) {
  dbReady = connectDB();
  dbReady.then(() => {
    app.listen(PORT, () => {
      console.log(`\n✅ Maswer Attend is running → http://localhost:${PORT}`);
      console.log(`📱 Scan page: http://localhost:${PORT}/scan\n`);
    });
  }).catch(err => { console.error('Could not connect to the database:', err.message); process.exit(1); });
}
