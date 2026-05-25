require('dotenv').config();

const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const FormData = require('form-data');
const { URL } = require('url');
const { execFileSync } = require('child_process');

const app = express();
app.disable('x-powered-by');
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const TMP_DIR = path.join(DATA_DIR, 'tmp');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const BRAND_NAME = process.env.BRAND_NAME || 'Custom AMP Panel';
const AGENT_TOKEN = process.env.PANEL_TO_AGENT_TOKEN || 'change-this-agent-token';
const TIMEOUT = Number(process.env.NODE_API_TIMEOUT_MS || 10000);
const UPGRADE_WEBSITE_URL = process.env.UPGRADE_WEBSITE_URL || process.env.SHOP_UPGRADE_URL || '';
const MAX_BODY_SIZE = process.env.MAX_BODY_SIZE || '20mb';
const TRUST_PROXY = Number(process.env.TRUST_PROXY || 1);
const API_ALLOWED_ORIGINS = String(process.env.API_CORS_ORIGIN || '*').split(',').map(s => s.trim()).filter(Boolean);
app.set('trust proxy', TRUST_PROXY);


const CLOUDFLARE_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN || '';
const CLOUDFLARE_ZONE_ID = process.env.CLOUDFLARE_ZONE_ID || '';
const CLOUDFLARE_ROOT_DOMAIN = String(process.env.CLOUDFLARE_ROOT_DOMAIN || '').toLowerCase().replace(/^\.+|\.+$/g, '');
const CLOUDFLARE_PROXIED = String(process.env.CLOUDFLARE_PROXIED || 'false').toLowerCase() === 'true';

const API_PERMISSIONS = [
  { key: 'server:start', label: 'Start server' },
  { key: 'server:stop', label: 'Stop server' },
  { key: 'server:restart', label: 'Restart server' },
  { key: 'backup:create', label: 'Make a backup' },
  { key: 'backup:download', label: 'Download a backup' },
  { key: 'console:read', label: 'See console logs' },
  { key: 'console:command', label: 'Send server commands' },
  { key: 'servers:list', label: 'List servers for bots' },
  { key: 'provision:user', label: 'Website: create users' },
  { key: 'provision:server', label: 'Website: create servers' },
  { key: 'network:ports', label: 'Manage extra network ports' },
  { key: 'provision:upgrade', label: 'Website: apply upgrades / resources' }
];

function hashApiKey(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}
function makeApiKey() {
  return `cap_${crypto.randomBytes(32).toString('hex')}`;
}
function extractApiToken(req) {
  const header = String(req.headers.authorization || '').trim();
  if (/^Bearer\s+/i.test(header)) return header.replace(/^Bearer\s+/i, '').trim();
  if (/^ApiKey\s+/i.test(header)) return header.replace(/^ApiKey\s+/i, '').trim();
  return String(req.headers['x-api-key'] || req.headers['x-panel-api-key'] || req.query.apiKey || req.query.key || '').trim();
}
function requireApiPermission(permission) {
  return (req, res, next) => {
    const raw = extractApiToken(req);
    if (!raw) return res.status(401).json({ ok: false, error: 'API key required. Send Authorization: Bearer YOUR_API_KEY or x-api-key.' });
    const db = readDb();
    const hash = hashApiKey(raw);
    const key = (db.apiKeys || []).find(k => k.hash === hash && !k.revokedAt);
    if (!key) return res.status(401).json({ ok: false, error: 'Invalid API key. Create a new key in the panel and copy the full key shown once.' });
    if (!key.permissions || !key.permissions.includes(permission)) return res.status(403).json({ ok: false, error: `API key missing permission: ${permission}` });
    const user = db.users.find(u => u.id === key.userId);
    if (!user) return res.status(401).json({ ok: false, error: 'API key user does not exist.' });
    key.lastUsedAt = new Date().toISOString();
    writeDb(db);
    req.apiUser = user;
    req.apiKey = key;
    next();
  };
}
function getApiServer(req, res) {
  const db = readDb();
  const server = db.servers.find(s => s.id === req.params.id || s.agentServerId === req.params.id);
  if (!server) { res.status(404).json({ error: 'Server not found.' }); return null; }
  if (req.apiUser.role !== 'admin' && server.ownerId !== req.apiUser.id) { res.status(403).json({ error: 'That server is not yours.' }); return null; }
  const node = db.nodes.find(n => n.id === server.nodeId);
  if (!node) { res.status(404).json({ error: 'Node missing.' }); return null; }
  return { db, server, node };
}
async function searchModrinth(query, gameVersion, addonKind = 'plugin', loaders = []) {
  const projectType = addonKind === 'mod' ? 'mod' : 'plugin';
  const facets = JSON.stringify([[`project_type:${projectType}`]]);
  const url = `https://api.modrinth.com/v2/search?limit=8&query=${encodeURIComponent(query)}&facets=${encodeURIComponent(facets)}`;
  const r = await fetch(url, { headers: { 'User-Agent': `${BRAND_NAME}/1.0` } });
  if (!r.ok) throw new Error(`Modrinth search failed: HTTP ${r.status}`);
  const data = await r.json();
  const results = [];
  for (const hit of (data.hits || []).slice(0, 8)) {
    let installUrl = '';
    try {
      const loaderList = loaders.length ? loaders : (projectType === 'mod' ? ['fabric','forge','neoforge','quilt'] : ['paper','spigot','bukkit','purpur']);
      const loaderParam = encodeURIComponent(JSON.stringify(loaderList));
      const versionsPart = gameVersion ? `&game_versions=${encodeURIComponent(JSON.stringify([gameVersion]))}` : '';
      const vr = await fetch(`https://api.modrinth.com/v2/project/${encodeURIComponent(hit.project_id)}/version?loaders=${loaderParam}${versionsPart}`, { headers: { 'User-Agent': `${BRAND_NAME}/1.0` } });
      if (vr.ok) {
        const versions = await vr.json();
        const primary = versions && versions[0] && ((versions[0].files || []).find(f => f.primary) || (versions[0].files || [])[0]);
        if (primary) installUrl = primary.url;
      }
    } catch {}
    results.push({
      source: 'Modrinth',
      type: hit.project_type === 'mod' ? 'mod' : 'plugin',
      name: hit.title,
      description: hit.description || '',
      iconUrl: hit.icon_url || '',
      projectUrl: `https://modrinth.com/${hit.project_type}/${hit.slug}`,
      installUrl
    });
  }
  return results;
}
async function searchSpiget(query) {
  const r = await fetch(`https://api.spiget.org/v2/search/resources/${encodeURIComponent(query)}?size=8&sort=-downloads`, { headers: { 'User-Agent': `${BRAND_NAME}/1.0` } });
  if (!r.ok) throw new Error(`Spiget search failed: HTTP ${r.status}`);
  const data = await r.json();
  return (Array.isArray(data) ? data : []).slice(0, 8).map(item => ({
    source: 'Spigot/Spiget',
    type: 'plugin',
    name: item.name,
    description: String(item.tag || item.description || '').replace(/<[^>]+>/g, '').slice(0, 180),
    iconUrl: item.icon && item.icon.url ? `https://www.spigotmc.org/${item.icon.url}` : '',
    projectUrl: `https://www.spigotmc.org/resources/${item.id}/`,
    installUrl: `https://api.spiget.org/v2/resources/${item.id}/download`
  }));
}
async function searchHangar(query) {
  const urls = [
    `https://hangar.papermc.io/api/v1/projects?query=${encodeURIComponent(query)}&limit=8&platform=PAPER`,
    `https://hangar.papermc.io/api/v1/projects?query=${encodeURIComponent(query)}&limit=8`
  ];
  let data = null;
  for (const url of urls) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': `${BRAND_NAME}/1.0` } });
      if (r.ok) { data = await r.json(); break; }
    } catch {}
  }
  const items = data && (data.result || data.results || data.projects || data.items || []);
  return (Array.isArray(items) ? items : []).slice(0, 8).map(item => {
    const owner = item.owner || item.namespace?.owner || item.user || '';
    const slug = item.slug || item.name || item.namespace?.slug || item.namespace?.project;
    return {
      source: 'Hangar',
      type: 'plugin',
      name: item.name || slug,
      description: item.description || item.desc || '',
      iconUrl: item.avatarUrl || item.avatar || '',
      projectUrl: owner && slug ? `https://hangar.papermc.io/${owner}/${slug}` : 'https://hangar.papermc.io/',
      installUrl: ''
    };
  });
}


const PLUGIN_CATALOG = [
  { type: 'plugin', name: 'LuckPerms', description: 'Permissions plugin for Minecraft servers.', url: 'https://download.luckperms.net/1565/bukkit/loader/LuckPerms-Bukkit-5.5.10.jar' },
  { type: 'plugin', name: 'ViaVersion', description: 'Allows newer versions to connect.', url: 'https://hangarcdn.papermc.io/plugins/ViaVersion/ViaVersion/versions/5.4.2/PAPER/ViaVersion-5.4.2.jar' },
  { type: 'plugin', name: 'ViaBackwards', description: 'Allows older versions to connect.', url: 'https://hangarcdn.papermc.io/plugins/ViaVersion/ViaBackwards/versions/5.4.2/PAPER/ViaBackwards-5.4.2.jar' },
  { type: 'plugin', name: 'SkinsRestorer', description: 'Restore and change skins on offline mode servers.', url: 'https://github.com/SkinsRestorer/SkinsRestorerX/releases/latest/download/SkinsRestorer.jar' },
  { type: 'plugin', name: 'EssentialsX', description: 'Modern essentials suite for Paper and Spigot.', url: 'https://github.com/EssentialsX/Essentials/releases/latest/download/EssentialsX.jar' },
  { type: 'plugin', name: 'Simple Tpa', description: 'Simple teleport request plugin.', url: 'https://github.com/May-2Beez/SimpleTpa/releases/latest/download/SimpleTpa.jar' },
  { type: 'mod', name: 'Fabric API', description: 'Core API dependency for Fabric mods.', url: 'https://cdn.modrinth.com/data/P7dR8mSH/versions/latest/Fabric-API.jar' },
  { type: 'mod', name: 'Sodium', description: 'Performance mod for Fabric.', url: 'https://cdn.modrinth.com/data/AANobbMI/versions/latest/Sodium.jar' }
];


const SERVER_TEMPLATES = [
  { key: 'PAPER', label: 'Minecraft Paper', category: 'Minecraft Java', game: 'minecraft-paper', image: 'itzg/minecraft-server:java21', envType: 'PAPER', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'plugins' },
  { key: 'PURPUR', label: 'Minecraft Purpur', category: 'Minecraft Java', game: 'minecraft-purpur', image: 'itzg/minecraft-server:java21', envType: 'PURPUR', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'plugins' },
  { key: 'SPIGOT', label: 'Minecraft Spigot', category: 'Minecraft Java', game: 'minecraft-spigot', image: 'itzg/minecraft-server:java21', envType: 'SPIGOT', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'plugins' },
  { key: 'BUKKIT', label: 'Minecraft Bukkit', category: 'Minecraft Java', game: 'minecraft-bukkit', image: 'itzg/minecraft-server:java21', envType: 'BUKKIT', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'plugins' },
  { key: 'PUFFERFISH', label: 'Minecraft Pufferfish', category: 'Minecraft Java', game: 'minecraft-pufferfish', image: 'itzg/minecraft-server:java21', envType: 'PUFFERFISH', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'plugins' },
  { key: 'FABRIC', label: 'Minecraft Fabric', category: 'Minecraft Modded', game: 'minecraft-fabric', image: 'itzg/minecraft-server:java21', envType: 'FABRIC', defaultPort: 25565, defaultMemoryMb: 3072, defaultStorageMb: 15360, addons: 'mods' },
  { key: 'QUILT', label: 'Minecraft Quilt', category: 'Minecraft Modded', game: 'minecraft-quilt', image: 'itzg/minecraft-server:java21', envType: 'QUILT', defaultPort: 25565, defaultMemoryMb: 3072, defaultStorageMb: 15360, addons: 'mods' },
  { key: 'FORGE', label: 'Minecraft Forge', category: 'Minecraft Modded', game: 'minecraft-forge', image: 'itzg/minecraft-server:java21', envType: 'FORGE', defaultPort: 25565, defaultMemoryMb: 4096, defaultStorageMb: 20480, addons: 'mods' },
  { key: 'NEOFORGE', label: 'Minecraft NeoForge', category: 'Minecraft Modded', game: 'minecraft-neoforge', image: 'itzg/minecraft-server:java21', envType: 'NEOFORGE', defaultPort: 25565, defaultMemoryMb: 4096, defaultStorageMb: 20480, addons: 'mods' },
  { key: 'MOHIST', label: 'Minecraft Mohist', category: 'Minecraft Hybrid', game: 'minecraft-mohist', image: 'itzg/minecraft-server:java21', envType: 'MOHIST', defaultPort: 25565, defaultMemoryMb: 4096, defaultStorageMb: 20480, addons: 'mods/plugins' },
  { key: 'MAGMA', label: 'Minecraft Magma', category: 'Minecraft Hybrid', game: 'minecraft-magma', image: 'itzg/minecraft-server:java21', envType: 'MAGMA', defaultPort: 25565, defaultMemoryMb: 4096, defaultStorageMb: 20480, addons: 'mods/plugins' },
  { key: 'VANILLA', label: 'Minecraft Vanilla', category: 'Minecraft Java', game: 'minecraft-vanilla', image: 'itzg/minecraft-server:java21', envType: 'VANILLA', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'none' },
  { key: 'CUSTOM', label: 'Minecraft Custom JAR', category: 'Minecraft Java', game: 'minecraft-custom-jar', image: 'itzg/minecraft-server:java21', envType: 'CUSTOM', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'plugins/mods' },
  { key: 'VELOCITY', label: 'Velocity Proxy', category: 'Minecraft Proxy', game: 'minecraft-velocity', image: 'itzg/mc-proxy', envType: 'VELOCITY', defaultPort: 25577, defaultMemoryMb: 512, defaultStorageMb: 2048, addons: 'plugins' },
  { key: 'BUNGEECORD', label: 'BungeeCord Proxy', category: 'Minecraft Proxy', game: 'minecraft-bungeecord', image: 'itzg/mc-proxy', envType: 'BUNGEECORD', defaultPort: 25577, defaultMemoryMb: 512, defaultStorageMb: 2048, addons: 'plugins' },
  { key: 'WATERFALL', label: 'Waterfall Proxy', category: 'Minecraft Proxy', game: 'minecraft-waterfall', image: 'itzg/mc-proxy', envType: 'WATERFALL', defaultPort: 25577, defaultMemoryMb: 512, defaultStorageMb: 2048, addons: 'plugins' },
  { key: 'RUST', label: 'Rust Dedicated Server', category: 'Survival Games', game: 'rust', image: 'didstopia/rust-server:latest', envType: 'RUST', defaultPort: 28015, defaultMemoryMb: 6144, defaultStorageMb: 30720, addons: 'oxide/plugins' },
  { key: 'TERRARIA', label: 'Terraria', category: 'Survival Games', game: 'terraria', image: 'ryshe/terraria:latest', envType: 'TERRARIA', defaultPort: 7777, defaultMemoryMb: 1024, defaultStorageMb: 5120, addons: 'world/files' },
  { key: 'VALHEIM', label: 'Valheim', category: 'Survival Games', game: 'valheim', image: 'lloesche/valheim-server:latest', envType: 'VALHEIM', defaultPort: 2456, defaultMemoryMb: 4096, defaultStorageMb: 20480, addons: 'mods/manual' },
  { key: 'FACTORIO', label: 'Factorio', category: 'Automation Games', game: 'factorio', image: 'factoriotools/factorio:stable', envType: 'FACTORIO', defaultPort: 34197, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'mods/manual' }
];
function gameTypeConfig(type) {
  const key = String(type || 'PAPER').toUpperCase();
  return SERVER_TEMPLATES.find(t => t.key === key) || SERVER_TEMPLATES[0];
}

function serverTypeKey(value) {
  const raw = String(value || '').toUpperCase();
  if (raw.includes('PAPER')) return 'PAPER';
  if (raw.includes('PURPUR')) return 'PURPUR';
  if (raw.includes('SPIGOT')) return 'SPIGOT';
  if (raw.includes('BUKKIT')) return 'BUKKIT';
  if (raw.includes('PUFFERFISH')) return 'PUFFERFISH';
  if (raw.includes('FABRIC')) return 'FABRIC';
  if (raw.includes('FORGE') && !raw.includes('NEOFORGE')) return 'FORGE';
  if (raw.includes('NEOFORGE')) return 'NEOFORGE';
  if (raw.includes('QUILT')) return 'QUILT';
  if (raw.includes('MOHIST')) return 'MOHIST';
  if (raw.includes('MAGMA')) return 'MAGMA';
  if (raw.includes('VELOCITY')) return 'VELOCITY';
  if (raw.includes('BUNGEE')) return 'BUNGEECORD';
  if (raw.includes('WATERFALL')) return 'WATERFALL';
  if (raw.includes('RUST')) return 'RUST';
  if (raw.includes('TERRARIA')) return 'TERRARIA';
  if (raw.includes('VALHEIM')) return 'VALHEIM';
  if (raw.includes('FACTORIO')) return 'FACTORIO';
  return raw || 'PAPER';
}
function addonInfo(server) {
  const type = serverTypeKey((server && (server.serverType || server.type || server.game)) || 'PAPER');
  if (['PAPER','PURPUR','SPIGOT','BUKKIT','PUFFERFISH','VELOCITY','BUNGEECORD','WATERFALL'].includes(type)) return { kind: 'plugin', folder: 'plugins', label: 'Plugins', loaders: ['paper','spigot','bukkit','purpur'] };
  if (['FABRIC','QUILT','FORGE','NEOFORGE','MOHIST','MAGMA'].includes(type)) return { kind: 'mod', folder: 'mods', label: type === 'MOHIST' || type === 'MAGMA' ? 'Mods / Plugins' : 'Mods', loaders: [type.toLowerCase()] };
  return { kind: 'none', folder: '', label: 'Add-ons', loaders: [] };
}
function userPortLimit(user) {
  return Number(user && (user.portSlots ?? user.networkPortSlots ?? 0)) || (user && user.role === 'admin' ? 999 : 0);
}
function usedPortSlots(db, userId) {
  return (db.servers || []).filter(s => s.ownerId === userId).reduce((total, srv) => total + ((srv.networkPorts || []).length), 0);
}
function userBackupLimit(user) {
  return Number(user && (user.backupSlots ?? 0)) || (user && user.role === 'admin' ? 999 : 0);
}
function userDatabaseLimit(user) {
  return Number(user && (user.databaseSlots ?? user.databases ?? 0)) || (user && user.role === 'admin' ? 999 : 0);
}
function countBackupItems(backups) {
  return Array.isArray(backups && backups.backups) ? backups.backups.length : 0;
}
function backupScheduleMs(value) {
  const v = String(value || 'off').toLowerCase();
  if (v === 'daily') return 24 * 60 * 60 * 1000;
  if (v === 'weekly') return 7 * 24 * 60 * 60 * 1000;
  if (v === 'monthly') return 30 * 24 * 60 * 60 * 1000;
  if (v === 'hourly') return 60 * 60 * 1000;
  return 0;
}
function normalizePortRecord(body) {
  const port = Number(body.port || body.publicPort);
  const protocol = String(body.protocol || body.type || 'tcp').toLowerCase() === 'udp' ? 'udp' : 'tcp';
  const containerPort = Number(body.containerPort || body.targetPort || port);
  return { port, publicPort: port, containerPort, type: protocol, protocol, notes: body.notes || '', createdAt: new Date().toISOString() };
}

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });
const upload = multer({ dest: TMP_DIR, limits: { fileSize: 1024 * 1024 * 1024 } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
const writeLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false });

function defaultDb() { return { users: [], nodes: [], servers: [], audit: [], apiKeys: [], plans: [] }; }
function normalizeDb(data) {
  data = data || defaultDb();
  data.users = data.users || [];
  data.nodes = data.nodes || [];
  data.servers = data.servers || [];
  data.audit = data.audit || [];
  data.apiKeys = data.apiKeys || [];
  data.plans = data.plans || [];
  for (const user of data.users) {
    user.subdomainSlots = Number(user.subdomainSlots || (user.role === 'admin' ? 999 : 0));
    user.portSlots = Number(user.portSlots ?? user.networkPortSlots ?? (user.role === 'admin' ? 999 : 0));
    user.backupSlots = Number(user.backupSlots ?? (user.role === 'admin' ? 999 : 1));
    user.databaseSlots = Number(user.databaseSlots ?? user.databases ?? (user.role === 'admin' ? 999 : 0));
  }
  for (const srv of data.servers) {
    srv.subusers = srv.subusers || [];
    srv.networkPorts = srv.networkPorts || [];
    srv.databases = srv.databases || [];
    srv.subdomains = srv.subdomains || [];
    srv.backupSchedule = srv.backupSchedule || { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null };
    srv.resourceStop = srv.resourceStop || null;
    srv.lastStopReason = srv.lastStopReason || null;
    srv.serverType = srv.serverType || serverTypeKey(srv.game || srv.type || 'PAPER');
    srv.networkPorts = (srv.networkPorts || []).map(p => Object.assign({}, p, { port: Number(p.port || p.publicPort), publicPort: Number(p.publicPort || p.port), containerPort: Number(p.containerPort || p.port || p.publicPort), type: p.type || p.protocol || 'tcp', protocol: p.protocol || p.type || 'tcp' }));
  }
  return data;
}
function postgresEnabled() { return !!process.env.DATABASE_URL; }
function psql(args, input) {
  return execFileSync('psql', [process.env.DATABASE_URL, ...args], {
    input,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe']
  });
}
function ensurePostgresState() {
  if (!postgresEnabled()) return false;
  try {
    psql(['-v', 'ON_ERROR_STOP=1', '-q', '-c', "CREATE TABLE IF NOT EXISTS panel_state (id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1), state JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());"]);
    const exists = psql(['-At', '-c', 'SELECT COUNT(*) FROM panel_state WHERE id = 1;']).trim();
    if (exists !== '1') {
      let seed = defaultDb();
      if (fs.existsSync(DB_FILE)) {
        try { seed = normalizeDb(JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch {}
      }
      const tag = `cap_${crypto.randomBytes(8).toString('hex')}`;
      psql(['-v', 'ON_ERROR_STOP=1', '-q', '-c', `INSERT INTO panel_state (id, state, updated_at) VALUES (1, $${tag}$${JSON.stringify(seed)}$${tag}$::jsonb, NOW()) ON CONFLICT (id) DO NOTHING;`]);
    }
    return true;
  } catch (e) {
    console.error('[WARN] PostgreSQL is configured but unavailable. Falling back to JSON db.json:', e.message);
    return false;
  }
}
function readDb() {
  if (ensurePostgresState()) {
    try {
      const raw = psql(['-At', '-c', 'SELECT state::text FROM panel_state WHERE id = 1;']).trim();
      if (raw) return normalizeDb(JSON.parse(raw));
    } catch (e) {
      console.error('[WARN] Could not read PostgreSQL panel_state. Falling back to JSON db.json:', e.message);
    }
  }
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(defaultDb(), null, 2));
  return normalizeDb(JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
}
function writeDb(db) {
  db = normalizeDb(db);
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  if (ensurePostgresState()) {
    try {
      const tag = `cap_${crypto.randomBytes(8).toString('hex')}`;
      psql(['-v', 'ON_ERROR_STOP=1', '-q', '-c', `UPDATE panel_state SET state = $${tag}$${JSON.stringify(db)}$${tag}$::jsonb, updated_at = NOW() WHERE id = 1;`]);
    } catch (e) {
      console.error('[WARN] Could not write PostgreSQL panel_state. JSON db.json was still saved:', e.message);
    }
  }
}
function addAudit(action, details = {}) {
  const db = readDb();
  db.audit.unshift({ id: uuidv4(), action, details, subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() });
  db.audit = db.audit.slice(0, 200);
  writeDb(db);
}
async function bootstrapAdmin() {
  const db = readDb();
  const email = process.env.ADMIN_EMAIL || 'admin@example.com';
  const password = process.env.ADMIN_PASSWORD || 'ChangeMe123!';
  const reset = String(process.env.RESET_ADMIN_ON_START || 'false').toLowerCase() === 'true';
  let user = db.users.find(u => String(u.email || '').toLowerCase() === String(email).toLowerCase());
  if (!user) {
    user = { id: uuidv4(), email, name: 'Admin', role: 'admin', subdomainSlots: 999, portSlots: 999, backupSlots: 999, databaseSlots: 999, subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() };
    db.users.push(user);
    console.log(`Created admin user: ${email}`);
  }
  if (reset || !user.passwordHash) {
    user.passwordHash = await bcrypt.hash(password, 10);
    console.log(`Admin password ${reset ? 'reset' : 'set'} for: ${email}`);
  }
  user.email = email;
  user.role = 'admin';
  user.subdomainSlots = Number(user.subdomainSlots || 999);
  user.portSlots = Number(user.portSlots || 999);
  user.backupSlots = Number(user.backupSlots || 999);
  user.databaseSlots = Number(user.databaseSlots || 999);
  writeDb(db);
}
function requireLogin(req, res, next) { if (!req.session.userId) return res.redirect('/login'); next(); }
function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || user.role !== 'admin') return res.status(403).render('error', { title: 'Forbidden', message: 'Admin access required.' });
  next();
}
function currentUser(req) { if (!req.session.userId) return null; return readDb().users.find(u => u.id === req.session.userId) || null; }
function agentUrl(node, route) { return `${node.url.replace(/\/$/, '')}${route}`; }
function agentToken(node) { return node.token || AGENT_TOKEN; }
function nodeHostFromUrl(url) { try { return new URL(url).hostname; } catch { return ''; } }
async function callAgent(node, route, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || TIMEOUT);
  try {
    const headers = Object.assign({}, options.headers || {});
    if (!headers.Authorization) headers.Authorization = `Bearer ${agentToken(node)}`;
    if (!headers['Content-Type'] && options.body && !(options.body instanceof Buffer)) headers['Content-Type'] = 'application/json';
    const response = await fetch(agentUrl(node, route), {
      method: options.method || 'GET',
      headers,
      body: options.body && headers['Content-Type'] === 'application/json' ? JSON.stringify(options.body) : options.body,
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `Agent returned HTTP ${response.status}`);
    return data;
  } finally { clearTimeout(timeout); }
}
async function fetchAgent(node, route, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeout || TIMEOUT * 10);
  try {
    const headers = Object.assign({ Authorization: `Bearer ${agentToken(node)}` }, options.headers || {});
    return await fetch(agentUrl(node, route), Object.assign({}, options, { headers, signal: controller.signal }));
  } finally { clearTimeout(timeout); }
}
function getOwnedServer(req, res) {
  const db = readDb();
  const user = currentUser(req);
  const server = db.servers.find(s => s.id === req.params.id);
  if (!server) return { error: () => res.status(404).render('error', { title: 'Not Found', message: 'Server not found.' }) };
  if (user.role !== 'admin' && server.ownerId !== user.id) return { error: () => res.status(403).render('error', { title: 'Forbidden', message: 'That server is not yours.' }) };
  const node = db.nodes.find(n => n.id === server.nodeId);
  if (!node) return { error: () => res.status(404).render('error', { title: 'Node missing', message: 'The node for this server is missing.' }) };
  return { db, user, server, node };
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'same-origin' }
}));
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true, limit: MAX_BODY_SIZE }));
app.use(express.json({ limit: MAX_BODY_SIZE }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  name: 'cap.sid',
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_SECURE === 'true', maxAge: 1000 * 60 * 60 * 12 }
}));
app.use(flash());
app.use((req, res, next) => { res.locals.brand = BRAND_NAME; res.locals.user = currentUser(req); res.locals.flash = { error: req.flash('error'), success: req.flash('success') }; next(); });

app.get('/', (req, res) => req.session.userId ? res.redirect('/dashboard') : res.redirect('/login'));
app.get('/login', (req, res) => res.render('login', { title: 'Login' }));
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = readDb().users.find(u => u.email.toLowerCase() === String(email || '').toLowerCase());
  if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) { req.flash('error', 'Invalid email or password.'); return res.redirect('/login'); }
  req.session.userId = user.id;
  res.redirect('/dashboard');
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/dashboard', requireLogin, (req, res) => {
  const db = readDb();
  const user = currentUser(req);
  const servers = user.role === 'admin' ? db.servers : db.servers.filter(s => s.ownerId === user.id);
  res.render('dashboard', { title: 'Dashboard', servers, nodes: db.nodes });
});

app.get('/api-keys', requireLogin, (req, res) => {
  const db = readDb();
  const user = currentUser(req);
  const apiKeys = db.apiKeys.filter(k => user.role === 'admin' || k.userId === user.id);
  res.render('api-keys', { title: 'API Keys', apiKeys, users: db.users, permissions: API_PERMISSIONS });
});

app.get('/servers/:id', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const filePath = req.query.path || '';
  let live = null, files = null, backups = null, plugins = null, mods = null, settings = null, ftp = null;
  try { live = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}`); } catch (e) { live = { error: e.message }; }
  try { files = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files?path=${encodeURIComponent(filePath)}`); } catch (e) { files = { error: e.message, items: [], path: filePath, parent: '' }; }
  try { backups = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`); } catch (e) { backups = { error: e.message, backups: [] }; }
  try { plugins = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files?path=plugins`); } catch (e) { plugins = { error: e.message, items: [] }; }
  try { mods = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files?path=mods`); } catch (e) { mods = { error: e.message, items: [] }; }
  try { settings = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/settings`); } catch (e) { settings = { error: e.message, settings: {} }; }
  try { ftp = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/ftp`); } catch (e) { ftp = { error: e.message, enabled: false }; }
  res.render('server', { title: ctx.server.name, server: ctx.server, node: ctx.node, live, files, backups, plugins, mods, settings, filePath, pluginCatalog: PLUGIN_CATALOG, addonInfo: addonInfo(ctx.server), allUsers: ctx.db.users, ftp, upgradeWebsiteUrl: UPGRADE_WEBSITE_URL, viewer: ctx.user });
});

app.post('/servers/:id/action', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const action = req.body.action;
  if (!['start', 'stop', 'restart'].includes(action)) { req.flash('error', 'Invalid action.'); return res.redirect(`/servers/${ctx.server.id}`); }
  try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/${action}`, { method: 'POST' }); req.flash('success', `${action} sent to agent.`); addAudit('server.action', { serverId: ctx.server.id, action, by: ctx.user.email }); }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}`);
});

app.post('/servers/:id/resources/upgrade', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  if (ctx.user.role !== 'admin') { req.flash('error', 'Only admins can directly change server resources. Use the upgrade button to buy more resources.'); return res.redirect(`/servers/${ctx.server.id}`); }
  const memoryMb = Math.max(128, Number(req.body.memoryMb || ctx.server.memoryMb || 2048));
  const cpuLimit = Math.max(0.1, Number(req.body.cpuLimit || ctx.server.cpuLimit || 1));
  const storageLimitMb = Math.max(512, Number(req.body.storageLimitMb || ctx.server.storageLimitMb || 10240));
  ctx.server.memoryMb = memoryMb;
  ctx.server.cpuLimit = cpuLimit;
  ctx.server.storageLimitMb = storageLimitMb;
  ctx.server.resourceStop = null;
  ctx.server.lastStopReason = null;
  writeDb(ctx.db);
  try {
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/resources`, { method: 'POST', timeout: TIMEOUT * 20, body: { memoryMb, cpuLimit, storageLimitMb, port: ctx.server.port, networkPorts: ctx.server.networkPorts || [] } });
    req.flash('success', 'Resources upgraded and Docker limits updated. You can start the server again now.');
    addAudit('server.resources.upgrade', { serverId: ctx.server.id, memoryMb, cpuLimit, storageLimitMb, by: ctx.user.email });
  } catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}`);
});

app.post('/servers/:id/command', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/command`, { method: 'POST', body: { command: req.body.command } }); req.flash('success', 'Command sent.'); }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#console`);
});
app.get('/servers/:id/logs.json', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/logs?lines=${encodeURIComponent(req.query.lines || '5000')}`)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/servers/:id/stats.json', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/stats`)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/servers/:id/files/download', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const response = await fetchAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/download?path=${encodeURIComponent(req.query.path || '')}`);
    if (!response.ok) throw new Error((await response.text()) || `Download failed: HTTP ${response.status}`);
    res.setHeader('Content-Disposition', response.headers.get('content-disposition') || 'attachment');
    res.setHeader('Content-Type', response.headers.get('content-type') || 'application/octet-stream');
    response.body.pipe(res);
  } catch (e) { req.flash('error', e.message); res.redirect(`/servers/${ctx.server.id}`); }
});
app.post('/servers/:id/files/upload', requireLogin, upload.array('files', 50), async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const uploaded = req.files || [];
  try {
    if (!uploaded.length) throw new Error('Pick at least one file to upload.');
    const form = new FormData();
    form.append('path', req.body.path || '');
    if (req.body.extractZip) form.append('extractZip', 'true');
    if (req.body.deleteZipAfterExtract) form.append('deleteZipAfterExtract', 'true');
    for (const file of uploaded) form.append('files', fs.createReadStream(file.path), file.originalname);
    const response = await fetchAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/upload`, { method: 'POST', headers: form.getHeaders(), body: form, timeout: TIMEOUT * 60 });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Upload failed.');
    req.flash('success', `${uploaded.length} file(s) uploaded${req.body.extractZip ? ' and ZIPs extracted' : ''}.`);
  } catch (e) { req.flash('error', e.message); }
  finally { for (const file of uploaded) fs.rmSync(file.path, { force: true }); }
  res.redirect(`/servers/${ctx.server.id}${req.body.path ? `?path=${encodeURIComponent(req.body.path)}` : ''}#files`);
});

app.post('/servers/:id/files/unzip', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/unzip`, { method: 'POST', body: { path: req.body.path, destination: req.body.destination || '' }, timeout: TIMEOUT * 30 });
    req.flash('success', 'ZIP extracted.');
  } catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}?path=${encodeURIComponent(req.body.currentPath || '')}#files`);
});
app.post('/servers/:id/files/mkdir', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/mkdir`, { method: 'POST', body: { path: req.body.path || '', name: req.body.name || 'new-folder' } }); req.flash('success', 'Folder created.'); }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}?path=${encodeURIComponent(req.body.path || '')}#files`);
});
app.post('/servers/:id/files/delete', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/delete`, { method: 'POST', body: { path: req.body.path } }); req.flash('success', 'Deleted.'); }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}?path=${encodeURIComponent(req.body.currentPath || '')}#files`);
});
app.get('/servers/:id/files/edit', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { const file = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/edit?path=${encodeURIComponent(req.query.path || '')}`); res.render('file-edit', { title: `Edit ${file.path}`, server: ctx.server, file }); }
  catch (e) { req.flash('error', e.message); res.redirect(`/servers/${ctx.server.id}#files`); }
});
app.post('/servers/:id/files/edit', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/edit`, { method: 'POST', body: { path: req.body.path, content: req.body.content } }); req.flash('success', 'File saved.'); }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}/files/edit?path=${encodeURIComponent(req.body.path || '')}`);
});


app.post('/servers/:id/saves/upload', requireLogin, writeLimiter, upload.single('save'), async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const form = new FormData();
    form.append('worldName', req.body.worldName || 'world');
    form.append('mode', req.body.mode || 'new');
    form.append('save', fs.createReadStream(req.file.path), req.file.originalname);
    const response = await fetchAgent(ctx.node, `/servers/${ctx.server.agentServerId}/saves/upload`, { method: 'POST', headers: form.getHeaders(), body: form, timeout: TIMEOUT * 120 });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Save upload failed.');
    req.flash('success', `Save uploaded to ${data.path || data.world}. Restart the server if needed.`);
  } catch (e) { req.flash('error', e.message); }
  finally { if (req.file) fs.rmSync(req.file.path, { force: true }); }
  res.redirect(`/servers/${ctx.server.id}#saves`);
});


app.get('/servers/:id/saves/world/download', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const worldName = req.query.worldName || 'world';
  try {
    const response = await fetchAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files/download?path=${encodeURIComponent(worldName)}`, { timeout: TIMEOUT * 60 });
    if (!response.ok) throw new Error((await response.text()) || `World download failed: HTTP ${response.status}`);
    res.setHeader('Content-Disposition', response.headers.get('content-disposition') || `attachment; filename="${worldName}.tar.gz"`);
    res.setHeader('Content-Type', response.headers.get('content-type') || 'application/gzip');
    response.body.pipe(res);
  } catch (e) { req.flash('error', e.message); res.redirect(`/servers/${ctx.server.id}#saves`); }
});

app.post('/servers/:id/backups/create', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const owner = ctx.db.users.find(u => u.id === ctx.server.ownerId) || {};
  try {
    const existing = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`);
    const used = countBackupItems(existing);
    const limit = userBackupLimit(owner);
    if (owner.role !== 'admin' && used >= limit) {
      req.flash('error', `No backup slots left. Used ${used}/${limit}. Delete a backup or buy more backup slots.`);
      return res.redirect(`/servers/${ctx.server.id}#backups`);
    }
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`, { method: 'POST', timeout: TIMEOUT * 60 });
    req.flash('success', 'Backup created.');
  } catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#backups`);
});

app.post('/servers/:id/backups/schedule', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const interval = String(req.body.interval || 'off').toLowerCase();
  const enabled = interval !== 'off';
  const ms = backupScheduleMs(interval);
  ctx.server.backupSchedule = {
    enabled,
    interval,
    keepLatest: Math.max(1, Number(req.body.keepLatest || 1)),
    lastRunAt: ctx.server.backupSchedule && ctx.server.backupSchedule.lastRunAt || null,
    nextRunAt: enabled && ms ? new Date(Date.now() + ms).toISOString() : null
  };
  writeDb(ctx.db);
  req.flash('success', enabled ? 'Automatic backup schedule saved.' : 'Automatic backups turned off.');
  res.redirect(`/servers/${ctx.server.id}#backups`);
});
app.get('/servers/:id/backups/:name', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const response = await fetchAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups/${encodeURIComponent(req.params.name)}`, { timeout: TIMEOUT * 30 });
    if (!response.ok) throw new Error((await response.text()) || `Backup download failed: HTTP ${response.status}`);
    res.setHeader('Content-Disposition', response.headers.get('content-disposition') || `attachment; filename="${req.params.name}"`);
    res.setHeader('Content-Type', response.headers.get('content-type') || 'application/gzip');
    response.body.pipe(res);
  } catch (e) { req.flash('error', e.message); res.redirect(`/servers/${ctx.server.id}#backups`); }
});
app.post('/servers/:id/backups/delete', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups/delete`, { method: 'POST', body: { name: req.body.name } }); req.flash('success', 'Backup deleted.'); }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#backups`);
});

app.post('/servers/:id/installer', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const info = addonInfo(ctx.server);
    if (info.kind === 'none') throw new Error('This game type does not support plugin/mod auto-install yet. Use the file manager instead.');
    const requestedType = req.body.type === 'mod' ? 'mod' : 'plugin';
    if (requestedType !== info.kind) throw new Error(`${info.label} only are allowed for this server type.`);
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/installer`, { method: 'POST', body: { type: info.kind, url: req.body.url }, timeout: TIMEOUT * 30 });
    req.flash('success', `${info.kind === 'mod' ? 'Mod' : 'Plugin'} installed. Restart the server if needed.`);
  }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#addons`);
});

app.post('/servers/:id/settings', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const payload = {
      serverType: req.body.serverType,
      version: req.body.version,
      motd: req.body.motd,
      seed: req.body.seed,
      levelType: req.body.levelType,
      difficulty: req.body.difficulty,
      gameMode: req.body.gameMode,
      maxPlayers: req.body.maxPlayers,
      onlineMode: req.body.onlineMode === 'true',
      pvp: req.body.pvp === 'true',
      allowFlight: req.body.allowFlight === 'true',
      spawnProtection: req.body.spawnProtection,
      viewDistance: req.body.viewDistance,
      simulationDistance: req.body.simulationDistance,
      customServerJar: req.body.customServerJar
    };
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/settings`, { method: 'POST', body: payload, timeout: TIMEOUT * 30 });
    req.flash('success', 'Server settings updated. Version changes recreate the container.');
  } catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#settings`);
});


app.get('/servers/:id/addons/search', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const info = addonInfo(ctx.server);
  const query = String(req.query.q || '').trim();
  const source = String(req.query.source || 'all').toLowerCase();
  if (!query) return res.json({ addonKind: info.kind, results: [] });
  if (info.kind === 'none') return res.json({ addonKind: info.kind, results: [] });
  const gameVersion = String(req.query.version || '').trim();
  const tasks = [];
  if (source === 'all' || source === 'modrinth') tasks.push(searchModrinth(query, gameVersion, info.kind, info.loaders).catch(e => [{ source: 'Modrinth', error: e.message }]));
  if (info.kind === 'plugin' && (source === 'all' || source === 'hangar')) tasks.push(searchHangar(query).catch(e => [{ source: 'Hangar', error: e.message }]));
  if (info.kind === 'plugin' && (source === 'all' || source === 'spigot' || source === 'spiget')) tasks.push(searchSpiget(query).catch(e => [{ source: 'Spigot/Spiget', error: e.message }]));
  const chunks = await Promise.all(tasks);
  const results = chunks.flat().filter(item => item.error || item.type === info.kind).slice(0, 24);
  res.json({ addonKind: info.kind, results });
});

app.post('/servers/:id/backups/restore', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups/restore`, { method: 'POST', body: { name: req.body.name }, timeout: TIMEOUT * 120 });
    req.flash('success', 'Backup restored. Server was restarted if it was online.');
  } catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#backups`);
});

app.get('/servers/:id/properties', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const data = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/properties`);
    res.render('properties-edit', { title: `Edit server.properties`, server: ctx.server, content: data.content || '' });
  } catch (e) { req.flash('error', e.message); res.redirect(`/servers/${ctx.server.id}#settings`); }
});

app.post('/servers/:id/properties', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/properties`, { method: 'POST', body: { content: req.body.content || '' } });
    req.flash('success', 'server.properties saved. Restart the server if needed.');
  } catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}/properties`);
});

app.post('/api-keys', requireLogin, (req, res) => {
  const db = readDb();
  const user = currentUser(req);
  const targetUserId = user.role === 'admin' && req.body.userId ? req.body.userId : user.id;
  const targetUser = db.users.find(u => u.id === targetUserId);
  if (!targetUser) { req.flash('error', 'User not found.'); return res.redirect('/api-keys'); }
  const permissions = Array.isArray(req.body.permissions) ? req.body.permissions : (req.body.permissions ? [req.body.permissions] : []);
  const allowed = API_PERMISSIONS.map(p => p.key);
  const cleanPermissions = permissions.filter(p => allowed.includes(p));
  const token = makeApiKey();
  db.apiKeys = db.apiKeys || [];
  db.apiKeys.push({
    id: uuidv4(),
    userId: targetUser.id,
    name: req.body.name || 'API Key',
    prefix: token.slice(0, 12),
    hash: hashApiKey(token),
    permissions: cleanPermissions,
    createdAt: new Date().toISOString(),
    lastUsedAt: null
  });
  writeDb(db);
  req.flash('success', `API key created. Copy it now: ${token}`);
  res.redirect('/api-keys');
});

app.post('/api-keys/:keyId/delete', requireLogin, (req, res) => {
  const db = readDb();
  const user = currentUser(req);
  const key = (db.apiKeys || []).find(k => k.id === req.params.keyId);
  if (!key) { req.flash('error', 'API key not found.'); return res.redirect('/api-keys'); }
  if (user.role !== 'admin' && key.userId !== user.id) { req.flash('error', 'You cannot delete that key.'); return res.redirect('/api-keys'); }
  key.revokedAt = new Date().toISOString();
  writeDb(db);
  req.flash('success', 'API key revoked.');
  res.redirect('/api-keys');
});

app.get('/api/v1/servers/:id/logs', requireApiPermission('console:read'), async (req, res) => {
  const ctx = getApiServer(req, res); if (!ctx) return;
  try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/logs?lines=${encodeURIComponent(req.query.lines || '5000')}`)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/v1/servers/:id/command', requireApiPermission('console:command'), async (req, res) => {
  const ctx = getApiServer(req, res); if (!ctx) return;
  try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/command`, { method: 'POST', body: { command: req.body.command } })); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/v1/servers/:id/start', requireApiPermission('server:start'), async (req, res) => {
  const ctx = getApiServer(req, res); if (!ctx) return;
  try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/start`, { method: 'POST' })); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/v1/servers/:id/stop', requireApiPermission('server:stop'), async (req, res) => {
  const ctx = getApiServer(req, res); if (!ctx) return;
  try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/stop`, { method: 'POST' })); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/v1/servers/:id/restart', requireApiPermission('server:restart'), async (req, res) => {
  const ctx = getApiServer(req, res); if (!ctx) return;
  try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/restart`, { method: 'POST' })); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/v1/servers/:id/backups', requireApiPermission('backup:create'), async (req, res) => {
  const ctx = getApiServer(req, res); if (!ctx) return;
  try {
    const owner = ctx.db.users.find(u => u.id === ctx.server.ownerId) || {};
    const existing = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`);
    const used = countBackupItems(existing);
    const limit = userBackupLimit(owner);
    if (owner.role !== 'admin' && used >= limit) return res.status(409).json({ ok: false, error: `No backup slots left. Used ${used}/${limit}.` });
    res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`, { method: 'POST', timeout: TIMEOUT * 60 }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/v1/servers/:id/backups/:name', requireApiPermission('backup:download'), async (req, res) => {
  const ctx = getApiServer(req, res); if (!ctx) return;
  try {
    const response = await fetchAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups/${encodeURIComponent(req.params.name)}`, { timeout: TIMEOUT * 30 });
    if (!response.ok) throw new Error((await response.text()) || `Backup download failed: HTTP ${response.status}`);
    res.setHeader('Content-Disposition', response.headers.get('content-disposition') || `attachment; filename="${req.params.name}"`);
    res.setHeader('Content-Type', response.headers.get('content-type') || 'application/gzip');
    response.body.pipe(res);
  } catch (e) { res.status(500).json({ error: e.message }); }
});



app.post('/servers/:id/subusers', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  if (ctx.user.role !== 'admin' && ctx.server.ownerId !== ctx.user.id) { req.flash('error', 'Only the owner or admin can manage subusers.'); return res.redirect(`/servers/${ctx.server.id}#subusers`); }
  const target = ctx.db.users.find(u => u.id === req.body.userId || u.email === req.body.email);
  if (!target) { req.flash('error', 'User not found. Create the user first.'); return res.redirect(`/servers/${ctx.server.id}#subusers`); }
  ctx.server.subusers = ctx.server.subusers || [];
  if (!ctx.server.subusers.some(su => su.userId === target.id)) {
    ctx.server.subusers.push({ userId: target.id, permissions: Array.isArray(req.body.permissions) ? req.body.permissions : (req.body.permissions ? [req.body.permissions] : []), subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() });
    writeDb(ctx.db);
  }
  req.flash('success', 'Subuser added.');
  res.redirect(`/servers/${ctx.server.id}#subusers`);
});
app.post('/servers/:id/subusers/remove', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  ctx.server.subusers = (ctx.server.subusers || []).filter(su => su.userId !== req.body.userId);
  writeDb(ctx.db);
  req.flash('success', 'Subuser removed.');
  res.redirect(`/servers/${ctx.server.id}#subusers`);
});
app.post('/servers/:id/network/ports', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  ctx.server.networkPorts = ctx.server.networkPorts || [];
  const record = normalizePortRecord(req.body);
  if (!record.port || record.port < 1 || record.port > 65535) { req.flash('error', 'Invalid public port.'); return res.redirect(`/servers/${ctx.server.id}#network`); }
  if (!record.containerPort || record.containerPort < 1 || record.containerPort > 65535) { req.flash('error', 'Invalid container port.'); return res.redirect(`/servers/${ctx.server.id}#network`); }
  const owner = ctx.db.users.find(u => u.id === ctx.server.ownerId) || ctx.user;
  const used = usedPortSlots(ctx.db, owner.id);
  const limit = userPortLimit(owner);
  if (owner.role !== 'admin' && used >= limit) { req.flash('error', `No extra port slots left. Used ${used}/${limit}. Ask an admin for more port slots.`); return res.redirect(`/servers/${ctx.server.id}#network`); }
  const portTaken = ctx.db.servers.some(s => Number(s.port) === record.port || (s.networkPorts || []).some(p => Number(p.port || p.publicPort) === record.port));
  if (portTaken) { req.flash('error', 'That public port is already used by another server.'); return res.redirect(`/servers/${ctx.server.id}#network`); }
  ctx.server.networkPorts.push(record);
  try {
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/resources`, { method: 'POST', timeout: TIMEOUT * 20, body: { memoryMb: ctx.server.memoryMb, cpuLimit: ctx.server.cpuLimit, storageLimitMb: ctx.server.storageLimitMb, port: ctx.server.port, networkPorts: ctx.server.networkPorts } });
    req.flash('success', 'Extra port added and Docker container recreated with the new binding.');
  } catch (e) {
    req.flash('error', `Port saved in panel, but the agent could not rebind Docker: ${e.message}`);
  }
  writeDb(ctx.db);
  res.redirect(`/servers/${ctx.server.id}#network`);
});
app.post('/servers/:id/network/ports/remove', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  ctx.server.networkPorts = (ctx.server.networkPorts || []).filter(p => String(p.port || p.publicPort) !== String(req.body.port));
  try {
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/resources`, { method: 'POST', timeout: TIMEOUT * 20, body: { memoryMb: ctx.server.memoryMb, cpuLimit: ctx.server.cpuLimit, storageLimitMb: ctx.server.storageLimitMb, port: ctx.server.port, networkPorts: ctx.server.networkPorts } });
    req.flash('success', 'Network port removed and Docker container recreated.');
  } catch (e) {
    req.flash('error', `Port removed in panel, but the agent could not rebind Docker: ${e.message}`);
  }
  writeDb(ctx.db);
  res.redirect(`/servers/${ctx.server.id}#network`);
});
app.post('/servers/:id/databases', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  ctx.server.databases = ctx.server.databases || [];
  const name = String(req.body.name || `${ctx.server.name}_db`).replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 48);
  ctx.server.databases.push({ id: uuidv4(), name, engine: req.body.engine || 'mysql', username: req.body.username || name, host: req.body.host || 'localhost', port: req.body.port || '3306', subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() });
  writeDb(ctx.db);
  req.flash('success', 'Database record added. This stores DB details now; automatic DB server creation can be wired next.');
  res.redirect(`/servers/${ctx.server.id}#database`);
});
app.post('/servers/:id/databases/remove', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  ctx.server.databases = (ctx.server.databases || []).filter(d => d.id !== req.body.databaseId);
  writeDb(ctx.db);
  req.flash('success', 'Database removed.');
  res.redirect(`/servers/${ctx.server.id}#database`);
});





function cloudflareEnabled() {
  return Boolean(CLOUDFLARE_API_TOKEN && CLOUDFLARE_ZONE_ID && CLOUDFLARE_ROOT_DOMAIN);
}
function isIpAddress(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(String(value || '').trim());
}
function normalizeSubdomain(hostname) {
  const clean = String(hostname || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^\.+|\.+$/g, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean)) throw new Error('Enter a valid domain or subdomain.');
  if (CLOUDFLARE_ROOT_DOMAIN && !clean.endsWith(`.${CLOUDFLARE_ROOT_DOMAIN}`) && clean !== CLOUDFLARE_ROOT_DOMAIN) {
    throw new Error(`Subdomain must be inside ${CLOUDFLARE_ROOT_DOMAIN}.`);
  }
  return clean;
}
async function cloudflareApi(method, endpoint, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${endpoint}`, {
    method,
    headers: {
      Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.success === false) {
    const message = data.errors && data.errors[0] ? data.errors[0].message : `Cloudflare HTTP ${response.status}`;
    throw new Error(message);
  }
  return data.result;
}
async function createCloudflareRecords({ hostname, target, port, serviceType }) {
  if (!cloudflareEnabled()) return { status: 'manual-dns-required', cloudflareEnabled: false };
  const dnsType = isIpAddress(target) ? 'A' : 'CNAME';
  const main = await cloudflareApi('POST', `/zones/${CLOUDFLARE_ZONE_ID}/dns_records`, {
    type: dnsType,
    name: hostname,
    content: target,
    ttl: 1,
    proxied: CLOUDFLARE_PROXIED
  });
  let srv = null;
  const svc = String(serviceType || 'java').toLowerCase();
  const makeSrv = async (service, proto, defaultPort) => cloudflareApi('POST', `/zones/${CLOUDFLARE_ZONE_ID}/dns_records`, {
    type: 'SRV',
    name: `${service}.${proto}.${hostname}`,
    data: { service, proto, name: hostname, priority: 0, weight: 5, port: Number(port), target: hostname },
    ttl: 1,
    proxied: false
  });
  if (svc === 'java' && Number(port) && Number(port) !== 25565) srv = await makeSrv('_minecraft', '_tcp', 25565);
  if (svc === 'bedrock' && Number(port) && Number(port) !== 19132) srv = await makeSrv('_minecraft', '_udp', 19132);
  // Rust generally uses A/CNAME plus visible port; no widely supported SRV fallback is created here.
  return { status: 'cloudflare-created', cloudflareEnabled: true, cloudflareRecordId: main.id, cloudflareSrvRecordId: srv ? srv.id : null, dnsType };
}
async function deleteCloudflareRecord(recordId) {
  if (!cloudflareEnabled() || !recordId) return;
  await cloudflareApi('DELETE', `/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${recordId}`);
}

app.post('/servers/:id/subdomains', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const hostname = normalizeSubdomain(req.body.hostname);
    const target = String(req.body.target || ctx.server.ipAddress || '').trim();
    const port = Number(req.body.port || ctx.server.port || 25565);
    if (!target) throw new Error('Target IP or hostname is required.');

    ctx.server.subdomains = ctx.server.subdomains || [];
    const owner = ctx.db.users.find(u => u.id === ctx.server.ownerId) || ctx.user;
    const slotLimit = Number(owner.subdomainSlots || 1);
    const usedSlots = ctx.db.servers.filter(s => s.ownerId === owner.id).reduce((total, srv) => total + ((srv.subdomains || []).length), 0);
    if (owner.role !== 'admin' && usedSlots >= slotLimit) throw new Error(`No subdomain slots left. Used ${usedSlots}/${slotLimit}. Ask an admin for more slots.`);

    const takenBy = ctx.db.servers.find(s => (s.subdomains || []).some(d => d.hostname === hostname));
    if (takenBy) throw new Error('That subdomain is taken by another server.');

    const serviceType = String(req.body.serviceType || (String(ctx.server.game || '').includes('rust') ? 'rust' : String(ctx.server.game || '').includes('bedrock') ? 'bedrock' : 'java')).toLowerCase();
    const cloudflare = await createCloudflareRecords({ hostname, target, port, serviceType });
    ctx.server.subdomains.push({
      id: uuidv4(),
      hostname,
      target,
      port,
      status: cloudflare.status,
      dnsType: cloudflare.dnsType || (isIpAddress(target) ? 'A' : 'CNAME'),
      serviceType,
      cloudflareRecordId: cloudflare.cloudflareRecordId || null,
      cloudflareSrvRecordId: cloudflare.cloudflareSrvRecordId || null,
      createdAt: new Date().toISOString()
    });
    writeDb(ctx.db);
    req.flash('success', cloudflare.cloudflareEnabled ? 'Subdomain created in Cloudflare.' : 'Subdomain saved. Add the DNS record manually or configure Cloudflare in panel/.env.');
  } catch (e) {
    req.flash('error', e.message);
  }
  res.redirect(`/servers/${ctx.server.id}#subdomains`);
});
app.post('/servers/:id/subdomains/remove', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const existing = (ctx.server.subdomains || []).find(d => d.id === req.body.subdomainId);
  try {
    if (existing) {
      await deleteCloudflareRecord(existing.cloudflareSrvRecordId);
      await deleteCloudflareRecord(existing.cloudflareRecordId);
    }
    ctx.server.subdomains = (ctx.server.subdomains || []).filter(d => d.id !== req.body.subdomainId);
    writeDb(ctx.db);
    req.flash('success', existing && existing.cloudflareRecordId ? 'Subdomain removed and Cloudflare DNS deleted.' : 'Subdomain removed from panel.');
  } catch (e) {
    req.flash('error', `Subdomain removed failed: ${e.message}`);
  }
  res.redirect(`/servers/${ctx.server.id}#subdomains`);
});

app.use('/api', (req, res, next) => {
  const origin = req.headers.origin;
  if (API_ALLOWED_ORIGINS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin && API_ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type, x-api-key, x-panel-api-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use('/api/', apiLimiter);
app.get('/api/v1/me', requireApiPermission('servers:list'), (req, res) => res.json({ ok: true, user: { id: req.apiUser.id, email: req.apiUser.email, role: req.apiUser.role }, permissions: req.apiKey.permissions || [] }));
app.get('/api/v1/server-templates', requireApiPermission('servers:list'), (req, res) => res.json({ ok: true, templates: SERVER_TEMPLATES }));
app.get('/api/v1/plans', requireApiPermission('servers:list'), (req, res) => { const db = readDb(); res.json({ ok: true, plans: db.plans || [] }); });
app.get('/api/servers', requireApiPermission('servers:list'), (req, res) => {
  const db = readDb();
  const servers = req.apiUser.role === 'admin' ? db.servers : db.servers.filter(s => s.ownerId === req.apiUser.id);
  res.json({ ok: true, servers: servers.map(s => ({ id: s.id, agentServerId: s.agentServerId, name: s.name, game: s.game, ipAddress: s.ipAddress, port: s.port, memoryMb: s.memoryMb, cpuLimit: s.cpuLimit, storageLimitMb: s.storageLimitMb })) });
});
app.get('/api/v1/servers', requireApiPermission('servers:list'), (req, res) => {
  const db = readDb();
  const servers = req.apiUser.role === 'admin' ? db.servers : db.servers.filter(s => s.ownerId === req.apiUser.id);
  res.json({ ok: true, servers: servers.map(s => ({ id: s.id, agentServerId: s.agentServerId, name: s.name, game: s.game, ipAddress: s.ipAddress, port: s.port, memoryMb: s.memoryMb, cpuLimit: s.cpuLimit, storageLimitMb: s.storageLimitMb })) });
});
app.post('/api/servers/:id/start', requireApiPermission('server:start'), async (req, res) => { const ctx = getApiServer(req, res); if (!ctx) return; try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/start`, { method: 'POST' })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/servers/:id/stop', requireApiPermission('server:stop'), async (req, res) => { const ctx = getApiServer(req, res); if (!ctx) return; try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/stop`, { method: 'POST' })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/servers/:id/restart', requireApiPermission('server:restart'), async (req, res) => { const ctx = getApiServer(req, res); if (!ctx) return; try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/restart`, { method: 'POST' })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/servers/:id/logs', requireApiPermission('console:read'), async (req, res) => { const ctx = getApiServer(req, res); if (!ctx) return; try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/logs?lines=${encodeURIComponent(req.query.lines || '5000')}`)); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/servers/:id/command', requireApiPermission('console:command'), async (req, res) => { const ctx = getApiServer(req, res); if (!ctx) return; try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/command`, { method: 'POST', body: { command: req.body.command } })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/servers/:id/backups', requireApiPermission('backup:create'), async (req, res) => { const ctx = getApiServer(req, res); if (!ctx) return; try { const owner = ctx.db.users.find(u => u.id === ctx.server.ownerId) || {}; const existing = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`); const used = countBackupItems(existing); const limit = userBackupLimit(owner); if (owner.role !== 'admin' && used >= limit) return res.status(409).json({ ok: false, error: `No backup slots left. Used ${used}/${limit}.` }); res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`, { method: 'POST', timeout: TIMEOUT * 60 })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/servers/:id/backups', requireApiPermission('backup:download'), async (req, res) => { const ctx = getApiServer(req, res); if (!ctx) return; try { res.json(await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`)); } catch (e) { res.status(500).json({ error: e.message }); } });

async function handleProvisionUser(req, res) {
  const db = readDb();
  try {
    const email = String(req.body.email || req.body.customerEmail || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: 'email is required.' });
    let user = db.users.find(u => String(u.email || '').toLowerCase() === email);
    let plainPassword = null;
    if (!user) {
      plainPassword = req.body.password || crypto.randomBytes(8).toString('hex');
      user = { id: uuidv4(), email, name: req.body.name || email, role: req.body.role === 'admin' && req.apiUser.role === 'admin' ? 'admin' : 'user', subdomainSlots: Number(req.body.subdomainSlots || 0), portSlots: Number(req.body.portSlots || 0), backupSlots: Number(req.body.backupSlots || 1), databaseSlots: Number(req.body.databaseSlots || 0), passwordHash: await bcrypt.hash(plainPassword, 10), createdAt: new Date().toISOString() };
      db.users.push(user);
    } else {
      user.name = req.body.name || user.name;
      user.subdomainSlots = Math.max(Number(user.subdomainSlots || 0), Number(req.body.subdomainSlots || 0));
      user.portSlots = Math.max(Number(user.portSlots || 0), Number(req.body.portSlots || 0));
      user.backupSlots = Math.max(Number(user.backupSlots || 0), Number(req.body.backupSlots || 0));
      user.databaseSlots = Math.max(Number(user.databaseSlots || 0), Number(req.body.databaseSlots || 0));
    }
    writeDb(db);
    res.json({ ok: true, user: { id: user.id, email: user.email, created: !!plainPassword, password: plainPassword }, loginUrl: process.env.PANEL_LOGIN_URL || '/login' });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
}

async function handleProvisionOrder(req, res) {
  const db = readDb();
  try {
    const email = String(req.body.email || req.body.customerEmail || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: 'email is required.' });
    let user = db.users.find(u => String(u.email || '').toLowerCase() === email);
    let plainPassword = null;
    if (!user) {
      if (!req.apiKey.permissions.includes('provision:user')) return res.status(403).json({ ok: false, error: 'API key missing permission: provision:user' });
      plainPassword = req.body.password || crypto.randomBytes(8).toString('hex');
      user = { id: uuidv4(), email, name: req.body.name || email, role: 'user', subdomainSlots: Number(req.body.subdomainSlots || 0), portSlots: Number(req.body.extraPorts || req.body.portSlots || 0), backupSlots: Number(req.body.backupSlots || 1), databaseSlots: Number(req.body.databaseSlots || req.body.databases || 0), subusers: [], networkPorts: [], databases: [], subdomains: [], passwordHash: await bcrypt.hash(plainPassword, 10), createdAt: new Date().toISOString() };
      db.users.push(user);
    }
    const plan = (db.plans || []).find(p => p.id === req.body.planId || p.name === req.body.planId || p.name === req.body.planName);
    if (plan && Number(plan.extraPorts || 0) > 0) user.portSlots = Math.max(userPortLimit(user), usedPortSlots(db, user.id) + Number(plan.extraPorts || 0));
    if (plan && Number(plan.backupSlots || 0) > 0) user.backupSlots = Math.max(userBackupLimit(user), Number(user.backupSlots || 0) + Number(plan.backupSlots || 0));
    if (plan && Number(plan.subdomainSlots || 0) > 0) user.subdomainSlots = Math.max(Number(user.subdomainSlots || 0), Number(user.subdomainSlots || 0) + Number(plan.subdomainSlots || 0));
    if (plan && Number(plan.databases || 0) > 0) user.databaseSlots = Math.max(userDatabaseLimit(user), Number(user.databaseSlots || 0) + Number(plan.databases || 0));
    const node = db.nodes.find(n => n.id === (req.body.nodeId || '')) || db.nodes[0];
    if (!node) return res.status(400).json({ ok: false, error: 'No node exists. Add a node first.' });
    const memoryMb = Number(req.body.memoryMb || (plan && plan.memoryMb) || 2048);
    const cpuLimit = Number(req.body.cpuLimit || (plan && plan.cpuLimit) || 1);
    const storageLimitMb = Number(req.body.storageLimitMb || (plan && plan.storageLimitMb) || 10240);
    const cfg = gameTypeConfig(req.body.serverType || req.body.type || req.body.gameType || 'PAPER');
    const port = Number(req.body.port || cfg.defaultPort || 25565);
    const portTaken = db.servers.some(s => Number(s.port) === port || (s.networkPorts || []).some(p => Number(p.port || p.publicPort) === port));
    if (portTaken) return res.status(409).json({ ok: false, error: `Port ${port} is already used by another server.` });
    const ipAddress = req.body.ipAddress || node.publicIp || nodeHostFromUrl(node.url);
    const name = req.body.serverName || req.body.nameOnPanel || `${(user.name || 'server').replace(/[^a-zA-Z0-9-]/g, '-')}-${Date.now()}`;
    const game = req.body.game || cfg.game;
    const image = req.body.image || cfg.image;
    const created = await callAgent(node, '/servers', { method: 'POST', body: { name, game, image, memoryMb, cpuLimit, storageLimitMb, ipAddress, port, env: { EULA: 'TRUE', TYPE: cfg.envType, VERSION: req.body.version || 'LATEST', MEMORY: `${Math.floor(memoryMb * 0.85)}M`, ENABLE_RCON: 'true', RCON_PASSWORD: req.body.rconPassword || crypto.randomBytes(12).toString('hex'), MOTD: name, CUSTOM_SERVER: req.body.customServerJar ? (String(req.body.customServerJar).startsWith('/') ? req.body.customServerJar : `/data/${req.body.customServerJar}`) : undefined } }, timeout: TIMEOUT * 60 });
    const panelServer = { id: uuidv4(), agentServerId: created.server.id, name, game, serverType: serverTypeKey(cfg.envType), ownerId: user.id, nodeId: node.id, memoryMb, cpuLimit, storageLimitMb, ipAddress, port, subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString(), orderId: req.body.orderId || req.body.checkoutId || null, planId: plan ? plan.id : (req.body.planId || null) };
    db.servers.push(panelServer);
    writeDb(db);
    res.json({ ok: true, user: { id: user.id, email: user.email, created: !!plainPassword, password: plainPassword }, server: panelServer, loginUrl: process.env.PANEL_LOGIN_URL || '/login' });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
}
app.post('/api/v1/provision/order', requireApiPermission('provision:server'), handleProvisionOrder);
app.post('/api/provision/order', requireApiPermission('provision:server'), handleProvisionOrder);
app.post('/api/admin/provision', requireApiPermission('provision:server'), handleProvisionOrder);
app.post('/api/v1/provision/user', requireApiPermission('provision:user'), handleProvisionUser);
app.post('/api/provision/user', requireApiPermission('provision:user'), handleProvisionUser);
app.post('/api/v1/provision/server', requireApiPermission('provision:server'), handleProvisionOrder);
app.post('/api/provision/server', requireApiPermission('provision:server'), handleProvisionOrder);



app.post('/servers/:id/delete', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  const confirmName = String(req.body.confirmName || '').trim();
  if (confirmName !== ctx.server.name) { req.flash('error', 'Server name confirmation did not match.'); return res.redirect(`/servers/${ctx.server.id}#settings`); }
  try {
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/delete`, { method: 'POST', timeout: TIMEOUT * 60 });
    ctx.db.servers = ctx.db.servers.filter(s => s.id !== ctx.server.id);
    writeDb(ctx.db);
    req.flash('success', 'Server deleted. Docker container, files, and backups were removed.');
    return res.redirect('/dashboard');
  } catch (e) { req.flash('error', e.message); return res.redirect(`/servers/${ctx.server.id}#settings`); }
});


app.get('/admin/import-docker/containers', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const node = db.nodes.find(n => n.id === req.query.nodeId) || db.nodes[0];
  if (!node) return res.status(400).json({ error: 'Add a node first.' });
  try { res.json(await callAgent(node, '/docker/containers', { timeout: TIMEOUT * 3 })); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/import-docker', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const node = db.nodes.find(n => n.id === req.body.nodeId) || db.nodes[0];
  const owner = db.users.find(u => u.id === req.body.ownerId);
  if (!node || !owner) { req.flash('error', 'Pick a valid node and owner.'); return res.redirect('/admin#import'); }
  try {
    const imported = await callAgent(node, '/docker/import', { method: 'POST', timeout: TIMEOUT * 5, body: {
      container: req.body.container,
      name: req.body.name,
      serverType: req.body.serverType,
      memoryMb: req.body.memoryMb,
      cpuLimit: req.body.cpuLimit,
      storageLimitMb: req.body.storageLimitMb,
      port: req.body.port,
      ipAddress: req.body.ipAddress || node.publicIp || nodeHostFromUrl(node.url),
      image: req.body.image,
      game: req.body.game,
      version: req.body.version,
      recreateManaged: req.body.recreateManaged === 'on'
    }});
    const agentServer = imported.server;
    const existing = db.servers.find(s => s.agentServerId === agentServer.id || s.name === req.body.name);
    const panelRecord = {
      id: existing ? existing.id : uuidv4(),
      agentServerId: agentServer.id,
      name: req.body.name || agentServer.name,
      game: agentServer.game || req.body.game || `minecraft-${String(req.body.serverType || 'paper').toLowerCase()}`,
      serverType: serverTypeKey(agentServer.env?.TYPE || req.body.serverType || agentServer.game),
      image: agentServer.image || req.body.image || '',
      ownerId: owner.id,
      nodeId: node.id,
      memoryMb: Number(req.body.memoryMb || agentServer.memoryMb || 2048),
      cpuLimit: Number(req.body.cpuLimit || agentServer.cpuLimit || 1),
      storageLimitMb: Number(req.body.storageLimitMb || agentServer.storageLimitMb || 10240),
      ipAddress: req.body.ipAddress || node.publicIp || nodeHostFromUrl(node.url),
      port: Number(req.body.port || agentServer.port || 25565),
      networkPorts: agentServer.networkPorts || [],
      subusers: [], databases: [], subdomains: [], imported: true,
      createdAt: existing ? existing.createdAt : new Date().toISOString()
    };
    if (existing) Object.assign(existing, panelRecord); else db.servers.push(panelRecord);
    writeDb(db);
    req.flash('success', 'Docker container imported into the panel.');
  } catch (e) { req.flash('error', e.message); }
  res.redirect('/admin#import');
});

app.post('/admin/servers/:id/resources', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const server = db.servers.find(s => s.id === req.params.id);
  if (!server) { req.flash('error', 'Server not found.'); return res.redirect('/admin#resources'); }
  const node = db.nodes.find(n => n.id === server.nodeId);
  if (!node) { req.flash('error', 'Node not found.'); return res.redirect('/admin#resources'); }
  server.memoryMb = Number(req.body.memoryMb || server.memoryMb || 2048);
  server.cpuLimit = Number(req.body.cpuLimit || server.cpuLimit || 1);
  server.storageLimitMb = Number(req.body.storageLimitMb || server.storageLimitMb || 10240);
  if (req.body.port) server.port = Number(req.body.port);
  try { await callAgent(node, `/servers/${server.agentServerId}/resources`, { method: 'POST', timeout: TIMEOUT * 10, body: { memoryMb: server.memoryMb, cpuLimit: server.cpuLimit, storageLimitMb: server.storageLimitMb, port: server.port, networkPorts: server.networkPorts || [] } }); }
  catch (e) { req.flash('error', `Saved in panel but agent failed to recreate container: ${e.message}`); }
  writeDb(db);
  req.flash('success', 'Server resources updated.');
  res.redirect('/admin#resources');
});


app.post('/servers/:id/ftp/reset', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const data = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/ftp/reset`, { method: 'POST', timeout: TIMEOUT * 30 });
    req.flash('success', `SFTP user created. Username: ${data.ftp.username} Password: ${data.ftp.password}`);
  } catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#ftp`);
});

app.post('/servers/:id/ftp/disable', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/ftp/disable`, { method: 'POST', timeout: TIMEOUT * 30 }); req.flash('success', 'SFTP access disabled.'); }
  catch (e) { req.flash('error', e.message); }
  res.redirect(`/servers/${ctx.server.id}#ftp`);
});

app.get('/admin', requireLogin, requireAdmin, (req, res) => { const db = readDb(); res.render('admin', { title: 'Admin', db, serverTemplates: SERVER_TEMPLATES }); });
app.post('/admin/nodes', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  db.nodes.push({
    id: uuidv4(),
    name: req.body.name,
    url: req.body.url,
    publicIp: req.body.publicIp || nodeHostFromUrl(req.body.url || ''),
    token: req.body.token || '',
    location: req.body.location || 'Unknown',
    createdAt: new Date().toISOString()
  });
  writeDb(db);
  req.flash('success', 'Node added.');
  res.redirect('/admin');
});
app.post('/admin/users', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  if (db.users.some(u => u.email.toLowerCase() === String(req.body.email).toLowerCase())) { req.flash('error', 'User already exists.'); return res.redirect('/admin'); }
  db.users.push({ id: uuidv4(), email: req.body.email, name: req.body.name || req.body.email, role: req.body.role || 'user', subdomainSlots: Number(req.body.subdomainSlots || 1), portSlots: Number(req.body.portSlots || 0), backupSlots: Number(req.body.backupSlots || 1), databaseSlots: Number(req.body.databaseSlots || 0), passwordHash: await bcrypt.hash(req.body.password || 'ChangeMe123!', 10), subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() });
  writeDb(db); req.flash('success', 'User created.'); res.redirect('/admin');
});

app.post('/admin/users/:id/resources', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) { req.flash('error', 'User not found.'); return res.redirect('/admin#users'); }
  user.subdomainSlots = Math.max(0, Number(req.body.subdomainSlots || 0));
  user.portSlots = Math.max(0, Number(req.body.portSlots || 0));
  user.backupSlots = Math.max(0, Number(req.body.backupSlots || 0));
  user.databaseSlots = Math.max(0, Number(req.body.databaseSlots || 0));
  writeDb(db);
  req.flash('success', 'User resource slots updated.');
  res.redirect('/admin#users');
});

app.post('/admin/servers', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const node = db.nodes.find(n => n.id === req.body.nodeId);
  const owner = db.users.find(u => u.id === req.body.ownerId);
  if (!node || !owner) { req.flash('error', 'Pick a valid node and owner.'); return res.redirect('/admin'); }
  try {
    const cfg = gameTypeConfig(req.body.serverType || req.body.type || 'PAPER');
    const memoryMb = Number(req.body.memoryMb || cfg.defaultMemoryMb || 2048);
    const cpuLimit = Number(req.body.cpuLimit || 1);
    const storageLimitMb = Number(req.body.storageLimitMb || cfg.defaultStorageMb || 10240);
    const port = Number(req.body.port || cfg.defaultPort || 25565);
    const ipAddress = req.body.ipAddress || node.publicIp || nodeHostFromUrl(node.url);
    const version = req.body.version || 'LATEST';
    const image = req.body.image || cfg.image;
    const game = req.body.game || cfg.game;
    const created = await callAgent(node, '/servers', { method: 'POST', body: {
      name: req.body.name,
      game,
      image,
      memoryMb,
      cpuLimit,
      storageLimitMb,
      ipAddress,
      port,
      env: {
        EULA: 'TRUE',
        TYPE: cfg.envType,
        VERSION: version,
        MEMORY: `${Math.floor(memoryMb * 0.85)}M`,
        ENABLE_RCON: 'true',
        RCON_PASSWORD: crypto.randomBytes(12).toString('hex'),
        MOTD: req.body.name || 'Minecraft Server',
        CUSTOM_SERVER: req.body.customServerJar ? (String(req.body.customServerJar).startsWith('/') ? req.body.customServerJar : `/data/${req.body.customServerJar}`) : undefined
      }
    }});
    db.servers.push({ id: uuidv4(), agentServerId: created.server.id, name: req.body.name, game, serverType: serverTypeKey(cfg.envType), ownerId: owner.id, nodeId: node.id, memoryMb, cpuLimit, storageLimitMb, ipAddress, port, subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() });
    writeDb(db); req.flash('success', 'Server created on node.');
  } catch (e) { req.flash('error', e.message); }
  res.redirect('/admin');
});


app.post('/admin/plans', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  db.plans = db.plans || [];
  db.plans.push({
    id: uuidv4(),
    name: req.body.name || 'New Plan',
    memoryMb: Number(req.body.memoryMb || 2048),
    cpuLimit: Number(req.body.cpuLimit || 1),
    storageLimitMb: Number(req.body.storageLimitMb || 10240),
    extraPorts: Number(req.body.extraPorts || 0),
    backupSlots: Number(req.body.backupSlots || 0),
    subdomainSlots: Number(req.body.subdomainSlots || 0),
    databases: Number(req.body.databases || 0),
    createdAt: new Date().toISOString()
  });
  writeDb(db);
  req.flash('success', 'Plan saved.');
  res.redirect('/admin#plans');
});


app.post('/admin/nodes/:id/update', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  const node = db.nodes.find(n => n.id === req.params.id);
  if (!node) { req.flash('error', 'Node not found.'); return res.redirect('/admin#nodes'); }
  node.name = req.body.name || node.name;
  node.url = req.body.url || node.url;
  node.publicIp = req.body.publicIp || node.publicIp || nodeHostFromUrl(node.url || '');
  node.token = req.body.token || node.token || '';
  node.location = req.body.location || 'Unknown';
  node.updatedAt = new Date().toISOString();
  writeDb(db);
  req.flash('success', 'Node updated.');
  res.redirect('/admin#nodes');
});

app.post('/admin/nodes/:id/delete', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  const inUse = db.servers.some(s => s.nodeId === req.params.id);
  if (inUse) { req.flash('error', 'Move or delete servers on this node before removing it.'); return res.redirect('/admin#nodes'); }
  db.nodes = db.nodes.filter(n => n.id !== req.params.id);
  writeDb(db);
  req.flash('success', 'Node removed.');
  res.redirect('/admin#nodes');
});

async function handleProvisionUpgrade(req, res) {
  const db = readDb();
  try {
    const email = String(req.body.email || req.body.customerEmail || '').trim().toLowerCase();
    const user = db.users.find(u => String(u.email || '').toLowerCase() === email) || db.users.find(u => u.id === req.body.userId);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found for upgrade.' });
    user.portSlots = Math.max(0, Number(user.portSlots || 0) + Number(req.body.portSlots || req.body.extraPorts || 0));
    user.backupSlots = Math.max(0, Number(user.backupSlots || 0) + Number(req.body.backupSlots || 0));
    user.subdomainSlots = Math.max(0, Number(user.subdomainSlots || 0) + Number(req.body.subdomainSlots || 0));
    user.databaseSlots = Math.max(0, Number(user.databaseSlots || 0) + Number(req.body.databaseSlots || req.body.databases || 0));
    const server = db.servers.find(s => s.id === req.body.serverId || s.agentServerId === req.body.serverId);
    if (server) {
      if (req.body.memoryMb) server.memoryMb = Math.max(Number(server.memoryMb || 0), Number(req.body.memoryMb));
      if (req.body.addMemoryMb) server.memoryMb = Number(server.memoryMb || 0) + Number(req.body.addMemoryMb);
      if (req.body.cpuLimit) server.cpuLimit = Math.max(Number(server.cpuLimit || 0), Number(req.body.cpuLimit));
      if (req.body.addCpuLimit) server.cpuLimit = Number(server.cpuLimit || 0) + Number(req.body.addCpuLimit);
      if (req.body.storageLimitMb) server.storageLimitMb = Math.max(Number(server.storageLimitMb || 0), Number(req.body.storageLimitMb));
      if (req.body.addStorageMb) server.storageLimitMb = Number(server.storageLimitMb || 0) + Number(req.body.addStorageMb);
      const node = db.nodes.find(n => n.id === server.nodeId);
      if (node) {
        await callAgent(node, `/servers/${server.agentServerId}/resources`, { method: 'POST', timeout: TIMEOUT * 20, body: { memoryMb: server.memoryMb, cpuLimit: server.cpuLimit, storageLimitMb: server.storageLimitMb, port: server.port, networkPorts: server.networkPorts || [] } });
      }
    }
    writeDb(db);
    res.json({ ok: true, user: { id: user.id, email: user.email, portSlots: user.portSlots, backupSlots: user.backupSlots, subdomainSlots: user.subdomainSlots, databaseSlots: user.databaseSlots }, server: server || null });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
}
app.post('/api/v1/provision/upgrade', requireApiPermission('provision:upgrade'), handleProvisionUpgrade);
app.post('/api/provision/upgrade', requireApiPermission('provision:upgrade'), handleProvisionUpgrade);
app.post('/api/admin/upgrade', requireApiPermission('provision:upgrade'), handleProvisionUpgrade);

async function runScheduledBackups() {
  const db = readDb();
  const now = Date.now();
  let changed = false;
  for (const server of db.servers) {
    const sched = server.backupSchedule || {};
    if (!sched.enabled || !backupScheduleMs(sched.interval)) continue;
    if (sched.nextRunAt && new Date(sched.nextRunAt).getTime() > now) continue;
    const node = db.nodes.find(n => n.id === server.nodeId);
    const owner = db.users.find(u => u.id === server.ownerId) || {};
    if (!node) continue;
    try {
      const existing = await callAgent(node, `/servers/${server.agentServerId}/backups`, { timeout: TIMEOUT * 3 });
      const used = countBackupItems(existing);
      const limit = userBackupLimit(owner);
      if (owner.role === 'admin' || used < limit) await callAgent(node, `/servers/${server.agentServerId}/backups`, { method: 'POST', timeout: TIMEOUT * 60 });
      sched.lastRunAt = new Date().toISOString();
      sched.nextRunAt = new Date(Date.now() + backupScheduleMs(sched.interval)).toISOString();
      server.backupSchedule = sched;
      changed = true;
    } catch (e) { console.error('[WARN] Scheduled backup failed for', server.name, e.message); }
  }
  if (changed) writeDb(db);
}
setInterval(runScheduledBackups, 5 * 60 * 1000);

app.get('/api/health', (req, res) => res.json({ ok: true, brand: BRAND_NAME, time: new Date().toISOString() }));
app.use((req, res) => res.status(404).render('error', { title: 'Not Found', message: 'Page not found.' }));
bootstrapAdmin().then(() => app.listen(PORT, () => console.log(`${BRAND_NAME} running on http://localhost:${PORT}`)));
