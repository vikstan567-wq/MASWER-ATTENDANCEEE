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

// Salary structure of an employee (monthly, FULL month). Old employees that only have
// a single "monthlySalary" are treated as Basic = monthlySalary.
const num = v => { const n = Number(v); return isFinite(n) && n > 0 ? n : 0; };
function structure(emp) {
  let basic = num(emp.basic), da = num(emp.da), hra = num(emp.hra), other = num(emp.otherAllow);
  if (basic + da + hra + other <= 0 && num(emp.monthlySalary) > 0) basic = num(emp.monthlySalary);
  return { basic, da, hra, other, full: r2(basic + da + hra + other) };
}
function offDaysIn(S, month) {
  let n = 0; const dim = daysInMonth(month);
  for (let d = 1; d <= dim; d++) if (S.weeklyOffDays.includes(dowOf(`${month}-${pad(d)}`))) n++;
  return n;
}
const whole = n => Math.round(n + 1e-9);

// One employee, one month — company payslip model:
//   DAYS IN MONTH  = calendar days minus weekly offs            (e.g. Sep 2026 -> 26)
//   PRESENT        = full days + 0.5 per half day
//   EXTRA DAYS     = days worked on a weekly off / holiday
//   EFFECTIVE DAYS = present + paid holidays + extra days + paid leave availed
//   Actual pay of each component = Full x effective / days-in-month (rounded to whole rupees)
//   emp      { id, name, basic, da, hra, otherAllow, projectPerDay, travelPerDay, foodPerDay,
//              pfAmount, esiAmount, profTax, monthlySalary (old), joiningDate }
//   adj      { leaveAvailed, leaveWages, extraDays } for this month (entered by HR)
//   leave    { opening } leave balance at the start of the month
function calcMonth({ emp, records, settings, advances, month, today, nowMs, adj, leave }) {
  const S = settingsWith(settings);
  adj = adj || {}; leave = leave || {};
  const dim = daysInMonth(month);
  const workDays = Math.max(1, dim - offDaysIn(S, month));
  const st = structure(emp), monthly = st.full;
  const perDay = monthly > 0 ? monthly / workDays : 0;
  const byDate = {};
  (records || []).forEach(r => { if (r.date && r.date.startsWith(month)) byDate[r.date] = r; });
  const holidays = {}; S.holidays.forEach(h => { holidays[h.date] = h.name || 'Holiday'; });
  nowMs = nowMs || Date.now();

  const days = [];
  const counts = { present: 0, half: 0, absent: 0, incomplete: 0, off: 0, holiday: 0, inprogress: 0, extra: 0 };
  let otHours = 0, lateCount = 0, running = 0;

  for (let d = 1; d <= dim; d++) {
    const date = `${month}-${pad(d)}`;
    const dow = dowOf(date);
    const rec = byDate[date];
    const row = { date, dow, status: '', label: '', in: rec ? rec.time : '', out: rec ? (rec.checkOut || '') : '', hours: null, late: false, credit: null, amount: 0, shift: rec ? rec.shift : '' };
    const workedOff = rec && rec.checkOut ? (() => { const h = recordHours(rec); row.hours = h; return (h !== null && S.halfDayBelowHours > 0 && h < S.halfDayBelowHours) ? 0.5 : 1; })() : 0;
    if (emp.joiningDate && date < emp.joiningDate) { row.status = 'prejoin'; row.label = 'Not joined'; }
    else if (date > today) { row.status = 'future'; row.label = '—'; }
    else if (S.weeklyOffDays.includes(dow)) { row.status = 'off'; row.label = workedOff ? 'Week off (worked)' : (holidays[date] || 'Week off'); row.credit = workedOff; counts.off++; counts.extra += workedOff; }
    else if (holidays[date] !== undefined) { row.status = 'holiday'; row.label = workedOff ? holidays[date] + ' (worked)' : holidays[date]; row.credit = 1 + workedOff; counts.holiday++; counts.extra += workedOff; }
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
    if (row.credit !== null && row.credit > 0) { row.amount = r2(row.credit * perDay); running += row.credit * perDay; }
    row.running = r2(running);
    days.push(row);
  }

  const present = counts.present + 0.5 * counts.half;
  const leaveAvailed = Math.max(0, Number(adj.leaveAvailed) || 0);
  const extraDays = r2(counts.extra + Math.max(0, Number(adj.extraDays) || 0));
  const effective = r2(present + counts.holiday + extraDays + leaveAvailed);
  const lop = Math.max(0, r2(counts.absent + counts.incomplete + 0.5 * counts.half - leaveAvailed));
  const act = x => whole(x * effective / workDays);

  const earnings = [];
  earnings.push({ name: 'BASIC', full: st.basic, actual: act(st.basic) });
  if (st.da) earnings.push({ name: 'DA', full: st.da, actual: act(st.da) });
  if (st.hra) earnings.push({ name: 'HRA', full: st.hra, actual: act(st.hra) });
  if (st.other) earnings.push({ name: 'OTHER ALLOWANCE', full: st.other, actual: act(st.other) });
  if (num(emp.projectPerDay)) earnings.push({ name: 'PROJECT ALLOWANCE', full: null, actual: whole(num(emp.projectPerDay) * present) });
  const leaveWages = num(adj.leaveWages);
  if (leaveWages) earnings.push({ name: 'LEAVE WITH WAGES', full: null, actual: whole(leaveWages) });
  const otPay = S.overtimeEnabled && perDay > 0 ? whole(otHours * (perDay / (S.overtimeHourlyBasis || 8)) * (S.overtimeRate || 1)) : 0;
  if (otPay) earnings.push({ name: 'OVERTIME', full: null, actual: otPay });
  const info = [];
  if (num(emp.travelPerDay)) info.push({ name: 'Travel', amount: whole(num(emp.travelPerDay) * present) });
  if (num(emp.foodPerDay)) info.push({ name: 'Food', amount: whole(num(emp.foodPerDay) * present) });
  const totalFull = r2(earnings.reduce((a, x) => a + (x.full || 0), 0));
  const totalActual = r2(earnings.reduce((a, x) => a + x.actual, 0));

  const chargeableLates = S.lateDeductionEnabled ? Math.max(0, lateCount - (S.lateFreePerMonth || 0)) : 0;
  const lateDeduction = whole(chargeableLates * (S.lateDeductionDays || 0) * perDay);
  const advance = r2((advances || []).reduce((a, x) => a + (Number(x.amount) || 0), 0));
  const ded = [];
  if (num(emp.pfAmount)) ded.push({ name: 'PF', amount: num(emp.pfAmount) });
  if (num(emp.esiAmount)) ded.push({ name: 'ESI', amount: num(emp.esiAmount) });
  if (num(emp.profTax)) ded.push({ name: 'PROF TAX', amount: num(emp.profTax) });
  if (lateDeduction) ded.push({ name: 'LATE DEDUCTION', amount: lateDeduction });
  if (advance) ded.push({ name: 'ADVANCE', amount: advance });
  const totalDed = r2(ded.reduce((a, x) => a + x.amount, 0));
  const net = Math.max(0, r2(totalActual - totalDed));
  const opening = Number(leave.opening) || 0;

  return {
    month, empId: emp.id, monthly, basis: workDays, perDay: r2(perDay), daysInMonth: dim, counts, earnedDays: effective,
    gross: r2(totalActual - otPay), overtime: { hours: r2(otHours), pay: otPay }, late: { count: lateCount, chargeable: chargeableLates, deduction: lateDeduction },
    advance, earnings: totalActual, deductions: totalDed, net, days,
    slip: { workDays, lop, effective, present, holidays: counts.holiday, extra: extraDays, otHours: r2(otHours),
      earnings, info, deductions: ded, totalFull, totalActual, totalDed,
      leave: { opening: r2(opening), availed: r2(leaveAvailed), closing: r2(opening - leaveAvailed) } },
    hasIncomplete: counts.incomplete > 0, monthOpen: days.some(x => x.status === 'future' || x.status === 'inprogress')
  };
}

module.exports = { DEFAULTS, settingsWith, calcMonth, structure, daysInMonth, recordHours, hm, r2 };
