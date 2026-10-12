// Supabase connection check + tables banata hai.  Chalane ke liye: CONNECT-SUPABASE.bat
const createPgDb = require('./pgdb');
const url = process.env.DATABASE_URL;
if (!url) { console.log('\n❌ DATABASE_URL nahi mila.'); process.exit(1); }
(async () => {
  try {
    const db = await createPgDb(url);
    const emps = db.collection('employees');
    const n = await emps.countDocuments();
    console.log('\n✅ SUPABASE CONNECT HO GAYA!');
    console.log('   Tables ban gaye: employees, attendance, settings');
    console.log('   Employees abhi: ' + n + '\n');
    process.exit(0);
  } catch (e) {
    console.log('\n❌ Connect nahi hua: ' + e.message);
    if (/password|authentication/i.test(e.message)) console.log('   → Password galat hai. Supabase me Reset database password karke dobara try karo.');
    if (/ENOTFOUND|timeout|ECONN/i.test(e.message)) console.log('   → Internet check karo, aur link me :6543 (Transaction pooler) hona chahiye.');
    process.exit(1);
  }
})();
