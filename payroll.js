// payroll.js — pure salary calculation (no database, no network).
// Works in Node (require) and is inlined into the single-file HTML edition.
//
// Day statuses:  present (1) · half (0.5) · absent (0) · incomplete (0, needs review)
//                off / holiday (paid or unpaid per settings) · inprogress (today, still open)
//                future / prejoin (not counted)

const DEFAULTS = {
  companyName: 'Your Company Name',
  companyAddress: '',
  logo: '',                 // data URL (png/jpg), optional
  currency: 'Rs.',
  daysMode: 'calendar',     // 'calendar' = actual days of the month, 'fixed30' = always 30
  halfDayBelowHours: 4,     // worked hours below this = half day (this or more = full day)
  weeklyOffDays: [0],       // 0 = Sunday ... 6 = Saturday
  weeklyOffPaid: true,
  holidays: [],             // [{ date: 'YYYY-MM-DD', name: 'Diwali' }]  (paid)
  overtimeEnabled: false,
  overtimeAfterHours: 9,    // hours beyond this on a day are overtime
  overtimeHourlyBasis: 8,   // hourly rate = per-day salary / this
  overtimeRate: 1.5,        // multiplier
  lateDeductionEnabled: false,
  lateFreePerMonth: 3,      // late marks allowed free
  lateDeductionDays: 0.25   // each extra late cuts this much of a day's salary
};

function settingsWith(s) {
  const o = { ...DEFAULTS, ...(s || {}) };
  o.halfDayBelowHours = Number(o.halfDayBelowHours) || 0;
  o.weeklyOffDays = Array.isArray(o.weeklyOffDays) ? o.weeklyOffDays.map(Number).filter(n => n >= 0 && n <= 6) : [0];
  o.holidays = Array.isArray(o.holidays) ? o.holidays.filter(h => h && /^\d{4}-\d{2}-\d{2}$/.test(h.date)) : [];
  return o;
}

const r2 = n => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
const pad = n => String(n).padStart(2, '0');

function daysInMonth(month) { const [y, m] = month.split('-').map(Number); return new Date(Date.UTC(y, m, 0)).getUTCDate(); }
function dowOf(dateStr) { return new Date(dateStr + 'T00:00:00Z').getUTCDay(); }

// "09:30 AM" / "04:48 pm" / "16:48" -> minutes since midnight
function toMinutes(t) {
  const m = /(\d{1,2}):(\d{2})\s*(AM|PM)?/i.exec(String(t || ''));
  if (!m) return null;
  let h = parseInt(m[1], 10); const mod = (m[3] || '').toUpperCase();
  if (mod === 'PM' && h !== 12) h += 12;
  if (mod === 'AM' && h === 12) h = 0;
  return h * 60 + parseInt(m[2], 10);
}
// worked hours (number) for a record; handles overnight (out earlier than in)
function recordHours(rec) {
  const m = /(\d+)h\s*(\d+)m/.exec(rec.totalHours || '');
  if (m) return parseInt(m[1], 10) + parseInt(m[2], 10) / 60;
  const a = toMinutes(rec.time), b = toMinutes(rec.checkOut);
  if (a === null || b === null) return null;
  let d = b - a; if (d < 0) d += 1440;
  return d / 60;
}
const hm = h => (h === null || h === undefined) ? '—' : `${Math.floor(h)}h ${pad(Math.round((h - Math.floor(h)) * 60))}m`;

// One employee, one month.
//   emp      { id, name, monthlySalary, joiningDate }
//   records  that employee's attendance records (any dates; filtered by month here)
//   advances [{ amount, ... }] for that month
//   today    'YYYY-MM-DD' (server's today, India time)
//   nowMs    Date.now() (to decide whether an open punch is still a live night shift)
function calcMonth({ emp, records, settings, advances, month, today, nowMs }) {
  const S = settingsWith(settings);
  const dim = daysInMonth(month);
  const basis = S.daysMode === 'fixed30' ? 30 : dim;
  const monthly = Number(emp.monthlySalary) || 0;
  const perDay = monthly > 0 ? monthly / basis : 0;
  const byDate = {};
  (records || []).forEach(r => { if (r.date && r.date.startsWith(month)) byDate[r.date] = r; });
  const holidays = {}; S.holidays.forEach(h => { holidays[h.date] = h.name || 'Holiday'; });
  nowMs = nowMs || Date.now();

  const days = [];
  const counts = { present: 0, half: 0, absent: 0, incomplete: 0, off: 0, holiday: 0, inprogress: 0 };
  let earnedDays = 0, running = 0, otHours = 0, lateCount = 0;

  for (let d = 1; d <= dim; d++) {
    const date = `${month}-${pad(d)}`;
    const dow = dowOf(date);
    const rec = byDate[date];
    const row = { date, dow, status: '', label: '', in: rec ? rec.time : '', out: rec ? (rec.checkOut || '') : '', hours: null, late: false, credit: null, amount: 0, shift: rec ? rec.shift : '' };
    if (emp.joiningDate && date < emp.joiningDate) { row.status = 'prejoin'; row.label = 'Not joined'; }
    else if (date > today) { row.status = 'future'; row.label = '—'; }
    else if (holidays[date] !== undefined) { row.status = 'holiday'; row.label = holidays[date]; row.credit = 1; counts.holiday++; }
    else if (S.weeklyOffDays.includes(dow)) { row.status = 'off'; row.label = 'Week off'; row.credit = S.weeklyOffPaid ? 1 : 0; counts.off++; }
    else if (!rec) { row.status = 'absent'; row.label = 'Absent'; row.credit = 0; counts.absent++; }
    else if (!rec.checkOut) {
      const age = rec.markedAt ? nowMs - new Date(rec.markedAt).getTime() : Infinity;
      if (date >= today || age < 20 * 3600 * 1000) { row.status = 'inprogress'; row.label = 'In progress'; row.credit = 0; counts.inprogress++; }
      else { row.status = 'incomplete'; row.label = 'Incomplete (missed punch-out)'; row.credit = 0; counts.incomplete++; }
    } else {
      const h = recordHours(rec); row.hours = h;
      row.late = rec.status === 'late';
      if (h !== null && S.halfDayBelowHours > 0 && h < S.halfDayBelowHours) { row.status = 'half'; row.label = 'Half day'; row.credit = 0.5; counts.half++; }
      else { row.status = 'present'; row.label = row.late ? 'Present (late)' : 'Present'; row.credit = 1; counts.present++; }
      if (row.late) lateCount++;
      if (S.overtimeEnabled && h !== null && h > S.overtimeAfterHours) otHours += h - S.overtimeAfterHours;
    }
    if (row.credit !== null) { earnedDays += row.credit; row.amount = r2(row.credit * perDay); running += row.credit * perDay; }
    row.running = r2(running);
    days.push(row);
  }

  const cappedDays = Math.min(earnedDays, basis);
  const gross = r2(cappedDays * perDay);
  const otPay = S.overtimeEnabled && perDay > 0 ? r2(otHours * (perDay / (S.overtimeHourlyBasis || 8)) * (S.overtimeRate || 1)) : 0;
  const chargeableLates = S.lateDeductionEnabled ? Math.max(0, lateCount - (S.lateFreePerMonth || 0)) : 0;
  const lateDeduction = r2(chargeableLates * (S.lateDeductionDays || 0) * perDay);
  const advance = r2((advances || []).reduce((a, x) => a + (Number(x.amount) || 0), 0));
  const earnings = r2(gross + otPay);
  const deductions = r2(lateDeduction + advance);
  const net = Math.max(0, r2(earnings - deductions));

  return {
    month, empId: emp.id, monthly, basis, perDay: r2(perDay), daysInMonth: dim, counts, earnedDays: r2(cappedDays),
    gross, overtime: { hours: r2(otHours), pay: otPay }, late: { count: lateCount, chargeable: chargeableLates, deduction: lateDeduction },
    advance, earnings, deductions, net, days,
    hasIncomplete: counts.incomplete > 0, monthOpen: days.some(x => x.status === 'future' || x.status === 'inprogress')
  };
}

module.exports = { DEFAULTS, settingsWith, calcMonth, daysInMonth, recordHours, hm, r2 };
