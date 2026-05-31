const fs     = require('fs');
const path   = require('path');
const bcrypt = require('bcryptjs');

const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'data.json');

const ROLES = ['basic','pro','premium','vip','vvip','tk','owner','high_owner','developer'];

function getDefault() {
  return {
    owner_hash: bcrypt.hashSync('VANCLA2K26', 10),
    attackers: [
      {
        id:         'axdikz-developer-001',
        username:   'AXDIKZ',
        password:   bcrypt.hashSync('AXDIKZ2026', 10),
        role:       'developer',
        twofa:      '676989',
        created_at: new Date().toISOString(),
        expires_at: null,
        banned:     false,
        ban_reason: ''
      }
    ],
    connect_codes:    [],
    redeem_codes:     [],
    accepted_sessions: {}
  };
}

function load() {
  try {
    if (!fs.existsSync(DB_FILE)) { save(getDefault()); return getDefault(); }
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!data.attackers.find(a => a.username === 'AXDIKZ')) {
      data.attackers.unshift({
        id: 'axdikz-developer-001', username: 'AXDIKZ',
        password: bcrypt.hashSync('AXDIKZ2026', 10),
        role: 'developer', twofa: '676989',
        created_at: new Date().toISOString(),
        expires_at: null, banned: false, ban_reason: ''
      });
      save(data);
    }
    return data;
  } catch(e) { return getDefault(); }
}

function save(data) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }
  catch(e) { console.error('DB error:', e.message); }
}

function get()      { return load(); }
function update(fn) { const d = load(); fn(d); save(d); }

module.exports = { get, update, ROLES };
