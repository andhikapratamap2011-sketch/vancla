const fs   = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'data.json');

function getDefault() {
  return {
    owner_hash: bcrypt.hashSync('OWNGANTENG001', 10),
    attackers: [],
    connect_codes: [],
    redeem_codes: []
  };
}

function load() {
  try {
    if (!fs.existsSync(DB_FILE)) { save(getDefault()); return getDefault(); }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch(e) { return getDefault(); }
}

function save(data) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
  catch(e) { console.error('DB save error:', e.message); }
}

function get()      { return load(); }
function update(fn) { const d = load(); fn(d); save(d); }

module.exports = { get, update };
