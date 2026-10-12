const path = require('path');
const fs = require('fs');
const http = require('http');

const PORT = 3000;

// ── Fix paths for pkg executable ──────────────────────────
// When running as .exe, __dirname points to temp folder
// We need to handle asset paths differently
const isPkg = typeof process.pkg !== 'undefined';
const basePath = isPkg ? path.dirname(process.execPath) : __dirname;

// Data directory - always next to the .exe file
const DATA_DIR = path.join(basePath, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Patch paths before loading server ────────────────────
process.env.DATA_DIR = DATA_DIR;
process.env.PUBLIC_DIR = isPkg
  ? path.join(path.dirname(process.execPath), 'public')
  : path.join(__dirname, 'public');
process.env.PORT = String(PORT);

// ── Start the express server ──────────────────────────────
process.env.START_SERVER = '1';
require('./server.js');

// ── Open browser after server starts ─────────────────────
function waitAndOpen(retries = 20) {
  setTimeout(() => {
    http.get(`http://localhost:${PORT}`, () => {
      // Server ready - open browser
      const { exec } = require('child_process');
      exec(`start http://localhost:${PORT}`);
      console.log('\n✅ Maswer Attend chal raha hai!');
      console.log(`🌐 Browser mein khul gaya: http://localhost:${PORT}`);
      console.log('\n⚠️  Yeh window band mat karna — app band ho jayega!');
      console.log('   (Minimize kar sakte ho)\n');
    }).on('error', () => {
      if (retries > 0) waitAndOpen(retries - 1);
    });
  }, 800);
}

waitAndOpen();
