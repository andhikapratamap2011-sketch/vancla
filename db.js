const fs   = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'data.json');

function getDefault() {
  return {
    owner_hash: bcrypt.hashSync('VANCLARAT2K26', 10),
    attackers: [],
    connect_codes: [],
    redeem_codes: []
  };
}

function load() {
  try {
    if (!fs.existsSync(DB_FILE)) { 
      const defaultData = getDefault();
      save(defaultData); 
      return defaultData; 
    }
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    // Ensure all required fields exist
    if (!data.owner_hash) data.owner_hash = getDefault().owner_hash;
    if (!data.attackers) data.attackers = [];
    if (!data.connect_codes) data.connect_codes = [];
    if (!data.redeem_codes) data.redeem_codes = [];
    return data;
  } catch(e) { 
    console.error('DB load error:', e.message);
    return getDefault(); 
  }
}

function save(data) {
  try { 
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); 
  } catch(e) { 
    console.error('DB save error:', e.message); 
  }
}

function get()      { return load(); }
function update(fn) { 
  const d = load(); 
  fn(d); 
  save(d); 
}

module.exports = { get, update };