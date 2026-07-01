require('dotenv').config();

const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const helmet = require('helmet');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const FormData = require('form-data');
const { URL } = require('url');
const { execFileSync } = require('child_process');
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;

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
const PANEL_DOMAINS = (process.env.PANEL_DOMAINS || '').split(',').map(d => d.trim()).filter(d => d);

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';

async function sendDiscordWebhook(title, description, color = 0x00ff00, fields = []) {
  if (!DISCORD_WEBHOOK_URL) return;
  try {
    await fetch(DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{
          title,
          description,
          color,
          fields,
          timestamp: new Date().toISOString()
        }]
      })
    });
  } catch (e) {
    console.error('Discord webhook error:', e.message);
  }
}

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
  { key: 'FACTORIO', label: 'Factorio', category: 'Automation Games', game: 'factorio', image: 'factoriotools/factorio:stable', envType: 'FACTORIO', defaultPort: 34197, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'mods/manual' },
  { key: 'ARK', label: 'ARK: Survival Evolved', category: 'Survival Games', game: 'ark', image: 'mbrounds/ark-server:latest', envType: 'ARK', defaultPort: 7777, defaultMemoryMb: 8192, defaultStorageMb: 51200, addons: 'mods/manual' },
  { key: 'CSGO', label: 'Counter-Strike 2', category: 'FPS Games', game: 'csgo', image: 'cm2network/csgo:latest', envType: 'CSGO', defaultPort: 27015, defaultMemoryMb: 2048, defaultStorageMb: 20480, addons: 'mods/manual' },
  { key: 'GTA', label: 'GTA V FiveM', category: 'Roleplay', game: 'gta-fivem', image: 'citizenm/fivem:latest', envType: 'FIVEM', defaultPort: 30120, defaultMemoryMb: 4096, defaultStorageMb: 30720, addons: 'resources' },
  { key: 'GARRYSMOD', label: 'Garry\'s Mod', category: 'Sandbox', game: 'garrysmod', image: 'cm2network/garrysmod:latest', envType: 'GARRYSMOD', defaultPort: 27015, defaultMemoryMb: 2048, defaultStorageMb: 20480, addons: 'addons' },
  { key: 'DAYZ', label: 'DayZ Standalone', category: 'Survival Games', game: 'dayz', image: 'cbolt/dayz-server:latest', envType: 'DAYZ', defaultPort: 2302, defaultMemoryMb: 4096, defaultStorageMb: 25600, addons: 'mods/manual' },
  { key: 'SEVEN_DAYS', label: '7 Days to Die', category: 'Survival Games', game: '7dtd', image: 'vinanrra/7dtd:latest', envType: 'SEVENDAYS', defaultPort: 26900, defaultMemoryMb: 4096, defaultStorageMb: 25600, addons: 'mods/manual' },
  { key: 'MINECRAFT_BEDROCK', label: 'Minecraft Bedrock', category: 'Minecraft Bedrock', game: 'minecraft-bedrock', image: 'itzg/minecraft-bedrock-server:latest', envType: 'BEDROCK', defaultPort: 19132, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'none' },
  { key: 'PALWORLD', label: 'Palworld', category: 'Survival Games', game: 'palworld', image: 'jammsen/palworld-dedicated-server:latest', envType: 'PALWORLD', defaultPort: 8211, defaultMemoryMb: 8192, defaultStorageMb: 51200, addons: 'mods/manual' },
  { key: 'SOTF', label: 'Sons of the Forest', category: 'Survival Games', game: 'sotf', image: 'steamgames/sotf:latest', envType: 'SOTF', defaultPort: 8766, defaultMemoryMb: 6144, defaultStorageMb: 30720, addons: 'mods/manual' },
  { key: 'UNTURNED', label: 'Unturned', category: 'Survival Games', game: 'unturned', image: 'jammsen/unturned:latest', envType: 'UNTURNED', defaultPort: 27015, defaultMemoryMb: 2048, defaultStorageMb: 15360, addons: 'mods/manual' },
  { key: 'SRCDS', label: 'Source Dedicated Server', category: 'FPS Games', game: 'srcds', image: 'cm2network/srcds:latest', envType: 'SRCDS', defaultPort: 27015, defaultMemoryMb: 2048, defaultStorageMb: 20480, addons: 'mods/manual' },
  { key: 'SATISFACTORY', label: 'Satisfactory', category: 'Automation Games', game: 'satisfactory', image: 'wolveix/satisfactory-server:latest', envType: 'SATISFACTORY', defaultPort: 7777, defaultMemoryMb: 6144, defaultStorageMb: 30720, addons: 'mods/manual' },
  { key: 'MORDHAU', label: 'Mordhau', category: 'FPS Games', game: 'mordhau', image: 'mbrounds/mordhau:latest', envType: 'MORDHAU', defaultPort: 7777, defaultMemoryMb: 4096, defaultStorageMb: 20480, addons: 'mods/manual' },
  { key: 'CONAN', label: 'Conan Exiles', category: 'Survival Games', game: 'conan-exiles', image: 'mbrounds/conan-exiles:latest', envType: 'CONAN', defaultPort: 7777, defaultMemoryMb: 6144, defaultStorageMb: 30720, addons: 'mods/manual' },
  { key: 'SQUAD', label: 'Squad', category: 'FPS Games', game: 'squad', image: 'mbrounds/squad:latest', envType: 'SQUAD', defaultPort: 7782, defaultMemoryMb: 6144, defaultStorageMb: 30720, addons: 'mods/manual' },
  { key: 'STARBOUND', label: 'Starbound', category: 'Survival Games', game: 'starbound', image: 'ryshe/starbound:latest', envType: 'STARBOUND', defaultPort: 21025, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'mods/manual' },
  { key: 'DONT_STARVE', label: 'Don\'t Starve Together', category: 'Survival Games', game: 'dont-starve-together', image: 'ryshe/dst-server:latest', envType: 'DST', defaultPort: 10999, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'mods/manual' },
  { key: 'PROJECT_ZOMBOID', label: 'Project Zomboid', category: 'Survival Games', game: 'project-zomboid', image: 'vinanrra/project-zomboid:latest', envType: 'ZOMBOID', defaultPort: 16261, defaultMemoryMb: 3072, defaultStorageMb: 15360, addons: 'mods/manual' },
  { key: 'MINECRAFT_LEGACY', label: 'Minecraft Legacy (1.8.9)', category: 'Minecraft Java', game: 'minecraft-legacy', image: 'itzg/minecraft-server:java8', envType: 'VANILLA', defaultPort: 25565, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'plugins/mods' },
  { key: 'ATLAS', label: 'ATLAS', category: 'Survival Games', game: 'atlas', image: 'mbrounds/atlas:latest', envType: 'ATLAS', defaultPort: 5755, defaultMemoryMb: 8192, defaultStorageMb: 51200, addons: 'mods/manual' },
  { key: 'NODEJS', label: 'Node.js App', category: 'Web Applications', game: 'nodejs', image: 'node:latest', envType: 'NODEJS', defaultPort: 3000, defaultMemoryMb: 512, defaultStorageMb: 5120, addons: 'npm' },
  { key: 'PYTHON', label: 'Python App', category: 'Web Applications', game: 'python', image: 'python:latest', envType: 'PYTHON', defaultPort: 8000, defaultMemoryMb: 512, defaultStorageMb: 5120, addons: 'pip' },
  { key: 'MARIADB', label: 'MariaDB Database', category: 'Databases', game: 'mariadb', image: 'mariadb:latest', envType: 'MARIADB', defaultPort: 3306, defaultMemoryMb: 1024, defaultStorageMb: 10240, addons: 'none' },
  { key: 'MYSQL', label: 'MySQL Database', category: 'Databases', game: 'mysql', image: 'mysql:latest', envType: 'MYSQL', defaultPort: 3306, defaultMemoryMb: 1024, defaultStorageMb: 10240, addons: 'none' },
  { key: 'POSTGRESQL', label: 'PostgreSQL Database', category: 'Databases', game: 'postgresql', image: 'postgres:latest', envType: 'POSTGRESQL', defaultPort: 5432, defaultMemoryMb: 1024, defaultStorageMb: 10240, addons: 'none' },
  { key: 'MINDUSTRY', label: 'Mindustry', category: 'Strategy Games', game: 'mindustry', image: 'anodynedev/mindustry-server:latest', envType: 'MINDUSTRY', defaultPort: 6567, defaultMemoryMb: 1024, defaultStorageMb: 5120, addons: 'mods/manual' },
  { key: 'SCRAP_MECHANIC', label: 'Scrap Mechanic', category: 'Survival Games', game: 'scrap-mechanic', image: 'thijsvanommen/scrap-mechanic:latest', envType: 'SCRAP', defaultPort: 4200, defaultMemoryMb: 2048, defaultStorageMb: 10240, addons: 'mods/manual' }
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

function defaultDb() { return { users: [], nodes: [], servers: [], audit: [], apiKeys: [], plans: [], subscriptions: [], payments: [], shopItems: [], shopPurchases: [], shopEnabled: false, signUpEnabled: true, passwordResetTokens: [], smtpConfig: { enabled: false, host: '', port: 587, secure: false, user: '', password: '', from: '' } }; }
function normalizeDb(data) {
  data = data || defaultDb();
  data.users = data.users || [];
  data.nodes = data.nodes || [];
  data.servers = data.servers || [];
  data.audit = data.audit || [];
  data.apiKeys = data.apiKeys || [];
  data.plans = data.plans || [];
  data.subscriptions = data.subscriptions || [];
  data.payments = data.payments || [];
  data.shopItems = data.shopItems || [];
  data.shopPurchases = data.shopPurchases || [];
  data.passwordResetTokens = data.passwordResetTokens || [];
  if (data.shopEnabled === undefined) data.shopEnabled = false;
  if (data.signUpEnabled === undefined) data.signUpEnabled = true;
  data.smtpConfig = data.smtpConfig || { enabled: false, host: '', port: 587, secure: false, user: '', password: '', from: '' };
  for (const user of data.users) {
    user.subdomainSlots = Number(user.subdomainSlots || (user.role === 'admin' ? 999 : 0));
    user.portSlots = Number(user.portSlots ?? user.networkPortSlots ?? (user.role === 'admin' ? 999 : 0));
    user.backupSlots = Number(user.backupSlots ?? (user.role === 'admin' ? 999 : 1));
    user.databaseSlots = Number(user.databaseSlots ?? user.databases ?? (user.role === 'admin' ? 999 : 0));
    user.creditBalance = Number(user.creditBalance || 0);
    user.totalSpent = Number(user.totalSpent || 0);
    user.avatar = user.avatar || null;
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
    user = { id: uuidv4(), email, name: 'Admin', role: 'admin', subdomainSlots: 999, portSlots: 999, backupSlots: 999, databaseSlots: 999, creditBalance: 0, totalSpent: 0, subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() };
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
app.get('/register', (req, res) => {
  const db = readDb();
  if (!db.signUpEnabled) {
    req.flash('error', 'Sign-ups are currently disabled.');
    return res.redirect('/login');
  }
  res.render('register', { title: 'Sign Up' });
});
app.post('/register', loginLimiter, async (req, res) => {
  const db = readDb();
  if (!db.signUpEnabled) {
    req.flash('error', 'Sign-ups are currently disabled.');
    return res.redirect('/login');
  }
  
  const { email, password, confirmPassword } = req.body;
  
  if (!email || !password || !confirmPassword) {
    req.flash('error', 'All fields are required.');
    return res.redirect('/register');
  }
  
  if (password !== confirmPassword) {
    req.flash('error', 'Passwords do not match.');
    return res.redirect('/register');
  }
  
  if (password.length < 8) {
    req.flash('error', 'Password must be at least 8 characters.');
    return res.redirect('/register');
  }
  
  if (db.users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
    req.flash('error', 'Email already registered.');
    return res.redirect('/register');
  }
  
  const newUser = {
    id: uuidv4(),
    email: email.toLowerCase(),
    name: email.split('@')[0],
    role: 'user',
    subdomainSlots: 1,
    portSlots: 0,
    backupSlots: 1,
    databaseSlots: 0,
    creditBalance: 0,
    totalSpent: 0,
    passwordHash: await bcrypt.hash(password, 10),
    subusers: [],
    networkPorts: [],
    databases: [],
    subdomains: [],
    backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null },
    createdAt: new Date().toISOString()
  };
  
  db.users.push(newUser);
  writeDb(db);
  req.flash('success', 'Account created successfully! Please log in.');
  res.redirect('/login');
});

app.get('/forgot-password', (req, res) => res.render('forgot-password', { title: 'Forgot Password' }));

app.post('/forgot-password', loginLimiter, async (req, res) => {
  const db = readDb();
  const { email } = req.body;
  
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  
  if (!user) {
    // Don't reveal if email exists or not for security
    req.flash('success', 'If an account exists with that email, a reset link has been sent.');
    return res.redirect('/login');
  }
  
  // Generate reset token
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  
  // Remove any existing tokens for this user
  db.passwordResetTokens = db.passwordResetTokens.filter(t => t.userId !== user.id);
  
  // Add new token
  db.passwordResetTokens.push({
    id: uuidv4(),
    userId: user.id,
    token,
    expiresAt
  });
  
  writeDb(db);
  
  // Send password reset email
  const resetLink = `${process.env.PUBLIC_BASE_URL || 'http://localhost:3000'}/reset-password?token=${token}`;
  
  if (db.smtpConfig && db.smtpConfig.enabled && db.smtpConfig.host && db.smtpConfig.from) {
    try {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: db.smtpConfig.host,
        port: db.smtpConfig.port,
        secure: db.smtpConfig.secure,
        auth: db.smtpConfig.user ? {
          user: db.smtpConfig.user,
          pass: db.smtpConfig.password
        } : undefined
      });
      
      await transporter.sendMail({
        from: db.smtpConfig.from,
        to: user.email,
        subject: 'Password Reset Request',
        text: `Hello ${user.name},\n\nYou requested a password reset. Click the link below to reset your password:\n\n${resetLink}\n\nThis link will expire in 1 hour.\n\nIf you did not request this, please ignore this email.`
      });
      
      console.log(`[PASSWORD RESET] Email sent to: ${user.email}`);
    } catch (e) {
      console.error(`[PASSWORD RESET] Failed to send email: ${e.message}`);
      // Fallback to console log if email fails
      console.log(`[PASSWORD RESET] Email: ${user.email}, Reset Link: ${resetLink}`);
    }
  } else {
    // Fallback to console log if SMTP not configured
    console.log(`[PASSWORD RESET] Email: ${user.email}, Reset Link: ${resetLink}`);
  }
  
  req.flash('success', 'If an account exists with that email, a reset link has been sent.');
  res.redirect('/login');
});

app.get('/reset-password', (req, res) => {
  const db = readDb();
  const { token } = req.query;
  
  const resetToken = db.passwordResetTokens.find(t => t.token === token);
  
  if (!resetToken || new Date(resetToken.expiresAt) < new Date()) {
    req.flash('error', 'Invalid or expired reset link.');
    return res.redirect('/forgot-password');
  }
  
  res.render('reset-password', { title: 'Reset Password', token });
});

app.post('/reset-password', loginLimiter, async (req, res) => {
  const db = readDb();
  const { token, password, confirmPassword } = req.body;
  
  if (!password || !confirmPassword) {
    req.flash('error', 'All fields are required.');
    return res.redirect(`/reset-password?token=${token}`);
  }
  
  if (password !== confirmPassword) {
    req.flash('error', 'Passwords do not match.');
    return res.redirect(`/reset-password?token=${token}`);
  }
  
  if (password.length < 8) {
    req.flash('error', 'Password must be at least 8 characters.');
    return res.redirect(`/reset-password?token=${token}`);
  }
  
  const resetToken = db.passwordResetTokens.find(t => t.token === token);
  
  if (!resetToken || new Date(resetToken.expiresAt) < new Date()) {
    req.flash('error', 'Invalid or expired reset link.');
    return res.redirect('/forgot-password');
  }
  
  const user = db.users.find(u => u.id === resetToken.userId);
  
  if (!user) {
    req.flash('error', 'User not found.');
    return res.redirect('/forgot-password');
  }
  
  // Update password
  user.passwordHash = await bcrypt.hash(password, 10);
  
  // Remove used token
  db.passwordResetTokens = db.passwordResetTokens.filter(t => t.token !== token);
  
  writeDb(db);
  
  req.flash('success', 'Password reset successfully! Please log in.');
  res.redirect('/login');
});

app.get('/profile', requireLogin, (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  res.render('profile', { title: 'Profile', user });
});

app.post('/profile/email', requireLogin, async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  const { email, currentPassword } = req.body;
  
  if (!email || !currentPassword) {
    req.flash('error', 'All fields are required.');
    return res.redirect('/profile');
  }
  
  if (!(await bcrypt.compare(currentPassword, user.passwordHash))) {
    req.flash('error', 'Current password is incorrect.');
    return res.redirect('/profile');
  }
  
  if (email.toLowerCase() !== user.email.toLowerCase() && db.users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
    req.flash('error', 'Email already in use.');
    return res.redirect('/profile');
  }
  
  user.email = email.toLowerCase();
  writeDb(db);
  req.flash('success', 'Email updated successfully.');
  res.redirect('/profile');
});

app.post('/profile/password', requireLogin, async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  const { currentPassword, newPassword, confirmPassword } = req.body;
  
  if (!currentPassword || !newPassword || !confirmPassword) {
    req.flash('error', 'All fields are required.');
    return res.redirect('/profile');
  }
  
  if (!(await bcrypt.compare(currentPassword, user.passwordHash))) {
    req.flash('error', 'Current password is incorrect.');
    return res.redirect('/profile');
  }
  
  if (newPassword !== confirmPassword) {
    req.flash('error', 'New passwords do not match.');
    return res.redirect('/profile');
  }
  
  if (newPassword.length < 8) {
    req.flash('error', 'Password must be at least 8 characters.');
    return res.redirect('/profile');
  }
  
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  writeDb(db);
  req.flash('success', 'Password updated successfully.');
  res.redirect('/profile');
});

app.post('/profile/avatar', requireLogin, upload.single('avatar'), async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  
  if (!req.file) {
    req.flash('error', 'Please select an image to upload.');
    return res.redirect('/profile');
  }
  
  // In production, you'd want to validate the file type and size
  // For now, we'll store it as a base64 data URL
  const fs = require('fs');
  const imageData = fs.readFileSync(req.file.path);
  const base64 = imageData.toString('base64');
  const mimeType = req.file.mimetype;
  
  // Clean up temp file
  fs.unlinkSync(req.file.path);
  
  user.avatar = `data:${mimeType};base64,${base64}`;
  writeDb(db);
  req.flash('success', 'Profile picture updated successfully.');
  res.redirect('/profile');
});

app.post('/profile/avatar/remove', requireLogin, (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  
  user.avatar = null;
  writeDb(db);
  req.flash('success', 'Profile picture removed.');
  res.redirect('/profile');
});

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password, token } = req.body;
  const user = readDb().users.find(u => u.email.toLowerCase() === String(email || '').toLowerCase());
  if (!user || !(await bcrypt.compare(password || '', user.passwordHash))) { req.flash('error', 'Invalid email or password.'); return res.redirect('/login'); }
  
  // Check 2FA if enabled
  if (user.twoFactorEnabled && user.twoFactorSecret) {
    if (!token) {
      req.session.tempUserId = user.id;
      return res.render('login-2fa', { title: 'Two-Factor Authentication', email: user.email });
    }
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: token,
      window: 2
    });
    if (!verified) {
      req.flash('error', 'Invalid 2FA code.');
      req.session.tempUserId = user.id;
      return res.render('login-2fa', { title: 'Two-Factor Authentication', email: user.email });
    }
  }
  
  req.session.userId = user.id;
  delete req.session.tempUserId;
  res.redirect('/dashboard');
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/2fa/setup', requireLogin, async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.redirect('/login');
  
  if (user.twoFactorEnabled) {
    req.flash('error', '2FA is already enabled. Disable it first to set up again.');
    return res.redirect('/dashboard');
  }
  
  // Generate secret
  const secret = speakeasy.generateSecret({
    name: `${BRAND_NAME} (${user.email})`,
    issuer: BRAND_NAME
  });
  
  // Generate QR code
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  
  // Store secret temporarily in session (not in DB until verified)
  req.session.tempTwoFactorSecret = secret.base32;
  
  res.render('2fa-setup', { title: 'Setup 2FA', qrCodeUrl, secret: secret.base32, email: user.email });
});

app.post('/2fa/verify-setup', requireLogin, async (req, res) => {
  const { token } = req.body;
  const secret = req.session.tempTwoFactorSecret;
  
  if (!secret) {
    req.flash('error', 'Setup session expired. Please start over.');
    return res.redirect('/2fa/setup');
  }
  
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2
  });
  
  if (!verified) {
    req.flash('error', 'Invalid code. Please try again.');
    return res.redirect('/2fa/setup');
  }
  
  // Save to database
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  if (user) {
    user.twoFactorSecret = secret;
    user.twoFactorEnabled = true;
    writeDb(db);
  }
  
  delete req.session.tempTwoFactorSecret;
  req.flash('success', 'Two-factor authentication enabled successfully!');
  res.redirect('/dashboard');
});

app.post('/2fa/disable', requireLogin, async (req, res) => {
  const { token, password } = req.body;
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  
  if (!user || !user.twoFactorEnabled) {
    req.flash('error', '2FA is not enabled.');
    return res.redirect('/dashboard');
  }
  
  // Verify password
  if (!(await bcrypt.compare(password || '', user.passwordHash))) {
    req.flash('error', 'Invalid password.');
    return res.redirect('/dashboard');
  }
  
  // Verify 2FA code
  const verified = speakeasy.totp.verify({
    secret: user.twoFactorSecret,
    encoding: 'base32',
    token: token,
    window: 2
  });
  
  if (!verified) {
    req.flash('error', 'Invalid 2FA code.');
    return res.redirect('/dashboard');
  }
  
  // Disable 2FA
  user.twoFactorEnabled = false;
  user.twoFactorSecret = null;
  writeDb(db);
  
  req.flash('success', 'Two-factor authentication disabled.');
  res.redirect('/dashboard');
});

app.get('/dashboard', requireLogin, (req, res) => {
  const db = readDb();
  const user = currentUser(req);
  const servers = user.role === 'admin' ? db.servers : db.servers.filter(s => s.ownerId === user.id);
  res.render('dashboard', { title: 'Dashboard', servers, nodes: db.nodes, allNodes: db.nodes });
});

app.post('/dashboard/bulk-action', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const action = req.body.action;
  const serverIds = req.body.serverIds;
  
  if (!action || !['start', 'stop', 'restart'].includes(action)) {
    req.flash('error', 'Invalid action.');
    return res.redirect('/dashboard');
  }
  
  if (!serverIds || !Array.isArray(serverIds)) {
    req.flash('error', 'No servers selected.');
    return res.redirect('/dashboard');
  }
  
  let successCount = 0;
  let failCount = 0;
  
  for (const serverId of serverIds) {
    const server = db.servers.find(s => s.id === serverId);
    if (!server) continue;
    
    const node = db.nodes.find(n => n.id === server.nodeId);
    if (!node) continue;
    
    try {
      await callAgent(node, `/servers/${server.agentServerId}/${action}`, { method: 'POST' });
      successCount++;
    } catch (e) {
      console.error(`Bulk ${action} failed for ${server.name}:`, e.message);
      failCount++;
    }
  }
  
  req.flash('success', `Bulk ${action} completed: ${successCount} succeeded, ${failCount} failed.`);
  res.redirect('/dashboard');
});

app.get('/api-keys', requireLogin, (req, res) => {
  const db = readDb();
  const user = currentUser(req);
  const apiKeys = db.apiKeys.filter(k => user.role === 'admin' || k.userId === user.id);
  res.render('api-keys', { title: 'API Keys', apiKeys, users: db.users, permissions: API_PERMISSIONS });
});

app.get('/status', async (req, res) => {
  const db = readDb();
  const nodesWithStatus = await Promise.all(db.nodes.map(async (node) => {
    const serversOnNode = db.servers.filter(s => s.nodeId === node.id);
    const previousStatus = node.status || 'unknown';
    try {
      const start = Date.now();
      await callAgent(node, '/health', { timeout: 5000 });
      const latency = Date.now() - start;
      const newStatus = 'up';
      
      // Send Discord webhook if node came back online
      if (previousStatus === 'down' || previousStatus === 'unknown') {
        await sendDiscordWebhook(
          'Node Online',
          `Node "${node.name}" is now online`,
          0x00ff00,
          [
            { name: 'Node', value: node.name },
            { name: 'Location', value: node.location || 'Unknown' },
            { name: 'Latency', value: `${latency}ms` },
            { name: 'Servers', value: serversOnNode.length.toString() }
          ]
        );
      }
      
      // Update node status in database
      node.status = newStatus;
      node.lastOnlineAt = new Date().toISOString();
      node.latencyMs = latency;
      writeDb(db);
      
      return { ...node, status: newStatus, latencyMs: latency, servers: serversOnNode.length, error: null };
    } catch (e) {
      const newStatus = 'down';
      
      // Send Discord webhook if node went offline
      if (previousStatus === 'up' || previousStatus === 'unknown') {
        await sendDiscordWebhook(
          'Node Offline',
          `Node "${node.name}" is now offline`,
          0xff0000,
          [
            { name: 'Node', value: node.name },
            { name: 'Location', value: node.location || 'Unknown' },
            { name: 'Error', value: e.message },
            { name: 'Servers', value: serversOnNode.length.toString() }
          ]
        );
      }
      
      // Update node status in database
      node.status = newStatus;
      node.lastDownAt = new Date().toISOString();
      node.latencyMs = null;
      writeDb(db);
      
      return { ...node, status: newStatus, latencyMs: null, servers: serversOnNode.length, error: e.message };
    }
  }));
  res.render('status', { title: 'Network Status', nodes: nodesWithStatus, servers: db.servers });
});

app.get('/servers/:id', requireLogin, async (req, res) => {
  try {
    const ctx = getOwnedServer(req, res);
    if (ctx.error) return ctx.error();
    const filePath = req.query.path || '';
    let live = null, files = null, backups = null, plugins = null, mods = null, settings = null, ftp = null, stats = null;
    try { live = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}`); } catch (e) { live = { error: e.message }; }
    try { files = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files?path=${encodeURIComponent(filePath)}`); } catch (e) { files = { error: e.message, items: [], path: filePath, parent: '' }; }
    try { backups = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups`); } catch (e) { backups = { error: e.message, backups: [] }; }
    try { plugins = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files?path=plugins`); } catch (e) { plugins = { error: e.message, items: [] }; }
    try { mods = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/files?path=mods`); } catch (e) { mods = { error: e.message, items: [] }; }
    try { settings = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/settings`); } catch (e) { settings = { error: e.message, settings: {} }; }
    try { ftp = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/ftp`); } catch (e) { ftp = { error: e.message, enabled: false }; }
    try { stats = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/stats`); } catch (e) { stats = { ok: false, error: e.message, cpu: 0, memory: { usage: '0B', percent: 0 }, network: { rx: '0B', tx: '0B' }, disk: { read: '0B', write: '0B' } }; }
    res.render('server', { title: ctx.server.name, server: ctx.server, node: ctx.node, live, files, backups, plugins, mods, settings, filePath, pluginCatalog: PLUGIN_CATALOG, addonInfo: addonInfo(ctx.server), allUsers: ctx.db.users, ftp, upgradeWebsiteUrl: UPGRADE_WEBSITE_URL, viewer: ctx.user, allNodes: ctx.db.nodes, stats });
  } catch (e) {
    console.error('Server page error:', e);
    res.status(500).render('error', { title: 'Internal Server Error', message: e.message });
  }
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
    
    // Apply retention policy before creating new backup
    const keepLatest = ctx.server.backupSchedule && ctx.server.backupSchedule.keepLatest ? ctx.server.backupSchedule.keepLatest : 1;
    const backupsList = existing.backups || [];
    if (backupsList.length >= keepLatest) {
      // Sort by creation date (oldest first)
      const sortedBackups = backupsList.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
      const toDelete = sortedBackups.slice(0, backupsList.length - keepLatest + 1);
      
      // Delete old backups
      for (const backup of toDelete) {
        try {
          await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/backups/${encodeURIComponent(backup.name)}`, { method: 'DELETE', timeout: TIMEOUT * 30 });
        } catch (e) {
          console.error(`Failed to delete old backup ${backup.name}:`, e.message);
        }
      }
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
    
    // Validate URL
    const url = String(req.body.url || '').trim();
    if (!url) throw new Error('URL is required.');
    if (!url.startsWith('http://') && !url.startsWith('https://')) throw new Error('URL must start with http:// or https://');
    
    // Call agent with improved error handling
    const result = await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/installer`, { method: 'POST', body: { type: info.kind, url }, timeout: TIMEOUT * 30 });
    
    // Check if agent returned an error
    if (result && result.error) throw new Error(result.error);
    
    req.flash('success', `${info.kind === 'mod' ? 'Mod' : 'Plugin'} installed successfully. Restart the server if needed.`);
  }
  catch (e) {
    console.error('Installer error:', e);
    const errorMsg = e.message || 'Unknown error occurred';
    if (errorMsg.includes('ETIMEDOUT') || errorMsg.includes('timeout')) {
      req.flash('error', 'Installation timed out. The file might be too large or the server is unreachable. Try again or use the file manager.');
    } else if (errorMsg.includes('ENOTFOUND') || errorMsg.includes('fetch failed')) {
      req.flash('error', 'Could not reach the download URL. Please check the URL and try again.');
    } else if (errorMsg.includes('404')) {
      req.flash('error', 'File not found at the provided URL. Please check the URL and try again.');
    } else {
      req.flash('error', `Installation failed: ${errorMsg}`);
    }
  }
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
    
    // Update storage location if changed
    if (req.body.storageLocation && req.body.storageLocation !== ctx.server.storageLocation) {
      ctx.server.storageLocation = req.body.storageLocation;
      writeDb(ctx.db);
    }
    
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
  
  // Restrict website linking permissions to admin only
  const restrictedPermissions = ['provision:server', 'provision:user'];
  const hasRestrictedPermission = cleanPermissions.some(p => restrictedPermissions.includes(p));
  if (hasRestrictedPermission && user.role !== 'admin') {
    req.flash('error', 'Website linking permissions (provision:server, provision:user) can only be created by admins.');
    return res.redirect('/api-keys');
  }
  
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
  
  // Enforce one database per server
  if (ctx.server.databases.length >= 1) {
    req.flash('error', 'One database per server is allowed.');
    return res.redirect(`/servers/${ctx.server.id}#database`);
  }
  
  // Check database slots
  const owner = ctx.db.users.find(u => u.id === ctx.server.ownerId) || ctx.user;
  const usedDatabases = ctx.db.servers.reduce((sum, s) => sum + (s.databases || []).length, 0);
  const databaseLimit = userDatabaseLimit(owner);
  if (owner.role !== 'admin' && usedDatabases >= databaseLimit) {
    req.flash('error', `No database slots left. Used ${usedDatabases}/${databaseLimit}. Ask an admin for more database slots.`);
    return res.redirect(`/servers/${ctx.server.id}#database`);
  }
  
  const name = String(req.body.name || `${ctx.server.name}_db`).replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 48);
  const engine = req.body.engine || 'mysql';
  
  // Auto-select port based on engine
  let defaultPort = 3306;
  if (engine === 'postgresql') defaultPort = 5432;
  if (engine === 'mariadb') defaultPort = 3307;
  
  // Find an available port
  const allDbPorts = ctx.db.servers.flatMap(s => (s.databases || []).map(d => d.port));
  let port = defaultPort;
  const maxPortAttempts = 100;
  let attempts = 0;
  while (attempts < maxPortAttempts && allDbPorts.includes(port)) {
    port++;
    attempts++;
  }
  
  // Auto-select database node (nodes with location containing 'database' or first available)
  let dbNode = ctx.db.nodes.find(n => String(n.location || '').toLowerCase().includes('database'));
  if (!dbNode) dbNode = ctx.db.nodes[0];
  if (!dbNode) {
    req.flash('error', 'No node available for database creation.');
    return res.redirect(`/servers/${ctx.server.id}#database`);
  }
  
  const dbRecord = { 
    id: uuidv4(), 
    name, 
    engine, 
    username: req.body.username || name, 
    password: req.body.password || crypto.randomBytes(16).toString('hex'),
    host: 'localhost', 
    port,
    nodeId: dbNode.id,
    createdAt: new Date().toISOString() 
  };
  
  ctx.server.databases.push(dbRecord);
  writeDb(ctx.db);
  req.flash('success', `Database created on node ${dbNode.name}. Port: ${port}`);
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
function normalizeSubdomain(hostname, allowCustom = false) {
  const clean = String(hostname || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].replace(/^\.+|\.+$/g, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean)) throw new Error('Enter a valid domain or subdomain.');
  
  // If custom domains are allowed, skip the root domain check
  if (allowCustom) return clean;
  
  // Check against panel domains if set
  if (PANEL_DOMAINS.length > 0) {
    const matchesPanelDomain = PANEL_DOMAINS.some(domain => clean.endsWith(`.${domain}`) || clean === domain);
    if (!matchesPanelDomain) throw new Error(`Domain must be one of: ${PANEL_DOMAINS.join(', ')}`);
  } else if (CLOUDFLARE_ROOT_DOMAIN && !clean.endsWith(`.${CLOUDFLARE_ROOT_DOMAIN}`) && clean !== CLOUDFLARE_ROOT_DOMAIN) {
    throw new Error(`Subdomain must be inside ${CLOUDFLARE_ROOT_DOMAIN}.`);
  }
  return clean;
}
async function cloudflareApi(method, endpoint, body) {
  try {
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
      console.error('Cloudflare API error:', message, data.errors);
      throw new Error(message);
    }
    return data.result;
  } catch (e) {
    console.error('Cloudflare API call failed:', e.message);
    throw e;
  }
}
async function createCloudflareRecords({ hostname, target, port, serviceType }) {
  if (!cloudflareEnabled()) {
    console.log('Cloudflare not enabled: API_TOKEN=', !!CLOUDFLARE_API_TOKEN, 'ZONE_ID=', !!CLOUDFLARE_ZONE_ID, 'ROOT_DOMAIN=', !!CLOUDFLARE_ROOT_DOMAIN);
    return { status: 'manual-dns-required', cloudflareEnabled: false };
  }
  try {
    const dnsType = isIpAddress(target) ? 'A' : 'CNAME';
    console.log('Creating Cloudflare DNS record:', { hostname, target, dnsType, port, serviceType });
    const main = await cloudflareApi('POST', `/zones/${CLOUDFLARE_ZONE_ID}/dns_records`, {
      type: dnsType,
      name: hostname,
      content: target,
      ttl: 1,
      proxied: CLOUDFLARE_PROXIED
    });
    console.log('Cloudflare main record created:', main.id);
    let srv = null;
    const svc = String(serviceType || 'java').toLowerCase();
    const makeSrv = async (service, proto, defaultPort) => cloudflareApi('POST', `/zones/${CLOUDFLARE_ZONE_ID}/dns_records`, {
      type: 'SRV',
      name: `${service}.${proto}.${hostname}`,
      data: { service, proto, name: hostname, priority: 0, weight: 5, port: Number(port), target: hostname },
      ttl: 1,
      proxied: false
    });
    if (svc === 'java' && Number(port) && Number(port) !== 25565) {
      srv = await makeSrv('_minecraft', '_tcp', 25565);
      console.log('Cloudflare SRV record created:', srv.id);
    }
    if (svc === 'bedrock' && Number(port) && Number(port) !== 19132) {
      srv = await makeSrv('_minecraft', '_udp', 19132);
      console.log('Cloudflare SRV record created:', srv.id);
    }
    // Rust generally uses A/CNAME plus visible port; no widely supported SRV fallback is created here.
    return { status: 'cloudflare-created', cloudflareEnabled: true, cloudflareRecordId: main.id, cloudflareSrvRecordId: srv ? srv.id : null, dnsType };
  } catch (e) {
    console.error('Failed to create Cloudflare records:', e.message);
    throw e;
  }
}
async function deleteCloudflareRecord(recordId) {
  if (!cloudflareEnabled() || !recordId) return;
  await cloudflareApi('DELETE', `/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${recordId}`);
}

app.post('/servers/:id/subdomains', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  try {
    const isCustomDomain = req.body.domainType === 'custom';
    const hostname = normalizeSubdomain(req.body.hostname, isCustomDomain);
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
    
    // Only create Cloudflare records if it's not a custom domain
    const cloudflare = isCustomDomain ? { status: 'manual-dns-required', cloudflareEnabled: false } : await createCloudflareRecords({ hostname, target, port, serviceType });
    
    ctx.server.subdomains.push({
      id: uuidv4(),
      hostname,
      target,
      port,
      status: cloudflare.status,
      dnsType: cloudflare.dnsType || (isIpAddress(target) ? 'A' : 'CNAME'),
      serviceType,
      isCustomDomain,
      cloudflareRecordId: cloudflare.cloudflareRecordId || null,
      cloudflareSrvRecordId: cloudflare.cloudflareSrvRecordId || null,
      createdAt: new Date().toISOString()
    });
    writeDb(ctx.db);
    if (isCustomDomain) {
      req.flash('success', 'Custom domain saved. Add the DNS record manually pointing to your server IP.');
    } else {
      req.flash('success', cloudflare.cloudflareEnabled ? 'Subdomain created in Cloudflare.' : 'Subdomain saved. Add the DNS record manually or configure Cloudflare in panel/.env.');
    }
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
      user = { id: uuidv4(), email, name: req.body.name || email, role: req.body.role === 'admin' && req.apiUser.role === 'admin' ? 'admin' : 'user', subdomainSlots: Number(req.body.subdomainSlots || 0), portSlots: Number(req.body.portSlots || 0), backupSlots: Number(req.body.backupSlots || 1), databaseSlots: Number(req.body.databaseSlots || 0), creditBalance: 0, totalSpent: 0, passwordHash: await bcrypt.hash(plainPassword, 10), createdAt: new Date().toISOString() };
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
      user = { id: uuidv4(), email, name: req.body.name || email, role: 'user', subdomainSlots: Number(req.body.subdomainSlots || 0), portSlots: Number(req.body.extraPorts || req.body.portSlots || 0), backupSlots: Number(req.body.backupSlots || 1), databaseSlots: Number(req.body.databaseSlots || req.body.databases || 0), creditBalance: 0, totalSpent: 0, subusers: [], networkPorts: [], databases: [], subdomains: [], passwordHash: await bcrypt.hash(plainPassword, 10), createdAt: new Date().toISOString() };
      db.users.push(user);
    }
    const plan = (db.plans || []).find(p => p.id === req.body.planId || p.name === req.body.planId || p.name === req.body.planName);
    if (plan && Number(plan.extraPorts || 0) > 0) user.portSlots = Math.max(userPortLimit(user), usedPortSlots(db, user.id) + Number(plan.extraPorts || 0));
    if (plan && Number(plan.backupSlots || 0) > 0) user.backupSlots = Math.max(userBackupLimit(user), Number(user.backupSlots || 0) + Number(plan.backupSlots || 0));
    if (plan && Number(plan.subdomainSlots || 0) > 0) user.subdomainSlots = Math.max(Number(user.subdomainSlots || 0), Number(user.subdomainSlots || 0) + Number(plan.subdomainSlots || 0));
    if (plan && Number(plan.databases || 0) > 0) user.databaseSlots = Math.max(userDatabaseLimit(user), Number(user.databaseSlots || 0) + Number(plan.databases || 0));
    
    // Node selection by location or ID
    let node = null;
    if (req.body.nodeId) {
      node = db.nodes.find(n => n.id === req.body.nodeId);
    } else if (req.body.location) {
      const locationLower = String(req.body.location).toLowerCase();
      node = db.nodes.find(n => String(n.location || '').toLowerCase().includes(locationLower));
    }
    if (!node) node = db.nodes[0];
    if (!node) return res.status(400).json({ ok: false, error: 'No node exists. Add a node first.' });
    
    const memoryMb = Number(req.body.memoryMb || (plan && plan.memoryMb) || 2048);
    const cpuLimit = Number(req.body.cpuLimit || (plan && plan.cpuLimit) || 1);
    const storageLimitMb = Number(req.body.storageLimitMb || (plan && plan.storageLimitMb) || 10240);
    const cfg = gameTypeConfig(req.body.serverType || req.body.type || req.body.gameType || 'PAPER');
    
    // Auto port selection with conflict detection
    let port = Number(req.body.port || cfg.defaultPort || 25565);
    const maxPortAttempts = 100;
    let attempts = 0;
    while (attempts < maxPortAttempts) {
      const portTaken = db.servers.some(s => Number(s.port) === port || (s.networkPorts || []).some(p => Number(p.port || p.publicPort) === port));
      if (!portTaken) break;
      port++;
      attempts++;
    }
    if (attempts >= maxPortAttempts) return res.status(409).json({ ok: false, error: 'Could not find an available port after 100 attempts.' });
    
    const ipAddress = req.body.ipAddress || node.publicIp || nodeHostFromUrl(node.url);
    const name = req.body.serverName || req.body.nameOnPanel || `${(user.name || 'server').replace(/[^a-zA-Z0-9-]/g, '-')}-${Date.now()}`;
    const game = req.body.game || cfg.game;
    const image = req.body.image || cfg.image;
    const created = await callAgent(node, '/servers', { method: 'POST', body: { name, game, image, memoryMb, cpuLimit, storageLimitMb, ipAddress, port, storageLocation: req.body.storageLocation || '/var/lib/docker', env: { EULA: 'TRUE', TYPE: cfg.envType, VERSION: req.body.version || 'LATEST', MEMORY: `${Math.floor(memoryMb * 0.85)}M`, ENABLE_RCON: 'true', RCON_PASSWORD: req.body.rconPassword || crypto.randomBytes(12).toString('hex'), MOTD: name, CUSTOM_SERVER: req.body.customServerJar ? (String(req.body.customServerJar).startsWith('/') ? req.body.customServerJar : `/data/${req.body.customServerJar}`) : undefined } }, timeout: TIMEOUT * 60 });
    const panelServer = { id: uuidv4(), agentServerId: created.server.id, name, game, serverType: serverTypeKey(cfg.envType), ownerId: user.id, nodeId: node.id, memoryMb, cpuLimit, storageLimitMb, ipAddress, port, storageLocation: req.body.storageLocation || '/var/lib/docker', subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString(), orderId: req.body.orderId || req.body.checkoutId || null, planId: plan ? plan.id : (req.body.planId || null) };
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
    const serverName = ctx.server.name;
    const userEmail = ctx.db.users.find(u => u.id === ctx.server.ownerId)?.email || 'Unknown';
    ctx.db.servers = ctx.db.servers.filter(s => s.id !== ctx.server.id);
    writeDb(ctx.db);
    
    await sendDiscordWebhook(
      'Server Deleted',
      `Server "${serverName}" was deleted by ${userEmail}`,
      0xff0000,
      [
        { name: 'Server', value: serverName },
        { name: 'User', value: userEmail },
        { name: 'Deleted At', value: new Date().toISOString() }
      ]
    );
    
    req.flash('success', 'Server deleted. Docker container, files, and backups were removed.');
    return res.redirect('/dashboard');
  } catch (e) { req.flash('error', e.message); return res.redirect(`/servers/${ctx.server.id}#settings`); }
});

app.post('/servers/:id/migrate', requireLogin, async (req, res) => {
  const ctx = getOwnedServer(req, res); if (ctx.error) return ctx.error();
  if (ctx.user.role !== 'admin') { req.flash('error', 'Only admins can migrate servers.'); return res.redirect(`/servers/${ctx.server.id}#settings`); }
  
  const targetNodeId = req.body.targetNodeId;
  const storageLocation = req.body.storageLocation || '/var/lib/docker';
  
  const targetNode = ctx.db.nodes.find(n => n.id === targetNodeId);
  if (!targetNode) { req.flash('error', 'Target node not found.'); return res.redirect(`/servers/${ctx.server.id}#settings`); }
  if (targetNodeId === ctx.server.nodeId) { req.flash('error', 'Cannot migrate to the same node.'); return res.redirect(`/servers/${ctx.server.id}#settings`); }
  
  try {
    // Stop the server on current node
    try { await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/stop`, { method: 'POST', timeout: TIMEOUT * 30 }); } catch (e) { console.error('Stop failed:', e); }
    
    // Delete server from current node
    await callAgent(ctx.node, `/servers/${ctx.server.agentServerId}/delete`, { method: 'POST', timeout: TIMEOUT * 60 });
    
    // Create server on new node
    const newServerData = await callAgent(targetNode, '/servers', {
      method: 'POST',
      timeout: TIMEOUT * 60,
      body: {
        name: ctx.server.name,
        image: ctx.server.image,
        port: ctx.server.port,
        ipAddress: ctx.server.ipAddress,
        memoryMb: ctx.server.memoryMb,
        cpuLimit: ctx.server.cpuLimit,
        storageLimitMb: ctx.server.storageLimitMb,
        game: ctx.server.game,
        env: ctx.server.env,
        networkPorts: ctx.server.networkPorts,
        storageLocation: storageLocation
      }
    });
    
    // Update database with new node and agent server ID
    ctx.server.nodeId = targetNodeId;
    ctx.server.agentServerId = newServerData.server.id;
    ctx.server.storageLocation = storageLocation;
    writeDb(ctx.db);
    
    req.flash('success', `Server migrated to ${targetNode.name}. Files will need to be manually transferred or restored from backup.`);
    res.redirect(`/servers/${ctx.server.id}#settings`);
  } catch (e) { 
    req.flash('error', `Migration failed: ${e.message}`); 
    res.redirect(`/servers/${ctx.server.id}#settings`); 
  }
});


app.get('/admin/import-docker/containers', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const node = db.nodes.find(n => n.id === req.query.nodeId) || db.nodes[0];
  if (!node) return res.status(400).json({ error: 'Add a node first.' });
  try { res.json(await callAgent(node, '/docker/containers', { timeout: TIMEOUT * 3 })); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/admin/nodes/:nodeId/storage-locations', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const node = db.nodes.find(n => n.id === req.params.nodeId);
  if (!node) return res.status(404).json({ error: 'Node not found.' });
  try {
    const data = await callAgent(node, '/storage-locations', { timeout: TIMEOUT * 5 });
    res.json({ ok: true, locations: data.locations || [] });
  } catch (e) {
    // If agent doesn't support storage-locations endpoint, return defaults
    res.json({ ok: true, locations: ['/var/lib/docker', '/mnt/ssd1', '/mnt/ssd2'] });
  }
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
      storageLocation: req.body.storageLocation || '/var/lib/docker',
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
      storageLocation: req.body.storageLocation || '/var/lib/docker',
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

app.post('/admin/servers/:id/delete', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const server = db.servers.find(s => s.id === req.params.id);
  if (!server) { req.flash('error', 'Server not found.'); return res.redirect('/admin#resources'); }
  const node = db.nodes.find(n => n.id === server.nodeId);
  if (!node) { req.flash('error', 'Node not found.'); return res.redirect('/admin#resources'); }
  try {
    await callAgent(node, `/servers/${server.agentServerId}/delete`, { method: 'POST', timeout: TIMEOUT * 60 });
    db.servers = db.servers.filter(s => s.id !== server.id);
    writeDb(db);
    req.flash('success', 'Server deleted. Docker container and all files were removed.');
  } catch (e) { req.flash('error', e.message); }
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

app.post('/admin/plans', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  const plan = {
    id: uuidv4(),
    name: req.body.name,
    price: Number(req.body.price),
    interval: req.body.interval || 'month',
    currency: req.body.currency || 'usd',
    memoryMb: Number(req.body.memoryMb || 2048),
    cpuLimit: Number(req.body.cpuLimit || 1),
    storageLimitMb: Number(req.body.storageLimitMb || 10240),
    stripePriceId: req.body.stripePriceId || '',
    createdAt: new Date().toISOString()
  };
  db.plans.push(plan);
  writeDb(db);
  req.flash('success', 'Plan created.');
  res.redirect('/admin#plans');
});

app.post('/admin/plans/:id/delete', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  db.plans = db.plans.filter(p => p.id !== req.params.id);
  writeDb(db);
  req.flash('success', 'Plan deleted.');
  res.redirect('/admin#plans');
});

app.post('/admin/shop/settings', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  db.shopEnabled = req.body.shopEnabled === 'true';
  db.signUpEnabled = req.body.signUpEnabled === 'true';
  writeDb(db);
  req.flash('success', 'Shop settings updated.');
  res.redirect('/admin#shop');
});

app.post('/admin/smtp/config', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  db.smtpConfig = {
    enabled: req.body.enabled === 'true',
    host: req.body.host || '',
    port: Number(req.body.port) || 587,
    secure: req.body.secure === 'true',
    user: req.body.user || '',
    password: req.body.password || '',
    from: req.body.from || ''
  };
  writeDb(db);
  req.flash('success', 'SMTP configuration saved.');
  res.redirect('/admin#shop');
});

app.post('/admin/smtp/test', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  const config = db.smtpConfig;
  
  if (!config.enabled || !config.host || !config.from) {
    req.flash('error', 'SMTP is not configured properly.');
    return res.redirect('/admin#shop');
  }
  
  try {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.user ? {
        user: config.user,
        pass: config.password
      } : undefined
    });
    
    await transporter.sendMail({
      from: config.from,
      to: config.user || config.from,
      subject: 'SMTP Test Email',
      text: 'This is a test email from your panel. If you received this, SMTP is configured correctly!'
    });
    
    req.flash('success', 'Test email sent successfully!');
  } catch (e) {
    req.flash('error', `Failed to send test email: ${e.message}`);
  }
  
  res.redirect('/admin#shop');
});

app.post('/admin/shop/items', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  const item = {
    id: uuidv4(),
    name: req.body.name,
    description: req.body.description,
    price: Number(req.body.price),
    nodeId: req.body.nodeId,
    game: req.body.game,
    image: req.body.image,
    memoryMb: Number(req.body.memoryMb),
    cpuLimit: Number(req.body.cpuLimit),
    storageLimitMb: Number(req.body.storageLimitMb),
    port: Number(req.body.port) || null,
    version: req.body.version,
    storageLocation: req.body.storageLocation || '/var/lib/docker',
    createdAt: new Date().toISOString()
  };
  db.shopItems = db.shopItems || [];
  db.shopItems.push(item);
  writeDb(db);
  req.flash('success', 'Shop item added.');
  res.redirect('/admin#shop');
});

app.post('/admin/shop/items/:id/delete', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  db.shopItems = db.shopItems.filter(i => i.id !== req.params.id);
  writeDb(db);
  req.flash('success', 'Shop item deleted.');
  res.redirect('/admin#shop');
});

app.get('/billing', requireLogin, (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  const subscriptions = db.subscriptions.filter(s => s.userId === user.id);
  const payments = db.payments.filter(p => p.userId === user.id);
  const shopPurchases = (db.shopPurchases || []).filter(p => p.userId === user.id);
  res.render('billing', { title: 'Billing', db, user, subscriptions, payments, shopPurchases });
});

app.get('/shop', requireLogin, (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  res.render('shop', { title: 'Shop', shopEnabled: db.shopEnabled, shopItems: db.shopItems || [], user, db });
});

app.post('/shop/purchase', requireLogin, async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  const item = db.shopItems.find(i => i.id === req.body.itemId);
  if (!item) { req.flash('error', 'Item not found.'); return res.redirect('/shop'); }
  if (!db.shopEnabled) { req.flash('error', 'Shop is closed.'); return res.redirect('/shop'); }
  
  const paymentMethod = req.body.paymentMethod;
  const serverName = req.body.serverName;
  
  if (paymentMethod === 'credit') {
    if (user.creditBalance < item.price) { req.flash('error', 'Insufficient credit balance.'); return res.redirect('/shop'); }
    user.creditBalance -= item.price;
    user.totalSpent += item.price;
  } else if (paymentMethod === 'stripe') {
    if (!STRIPE_SECRET_KEY) { req.flash('error', 'Stripe not configured.'); return res.redirect('/shop'); }
    // Create Stripe checkout session
    try {
      const checkoutSession = await stripe.checkout.sessions.create({
        mode: 'payment',
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: { name: item.name },
            unit_amount: Math.round(item.price * 100),
          },
          quantity: 1,
        }],
        success_url: `${process.env.PUBLIC_BASE_URL || 'http://localhost:3000'}/shop/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.PUBLIC_BASE_URL || 'http://localhost:3000'}/shop`,
        customer_email: user.email,
        metadata: {
          userId: user.id,
          itemId: item.id,
          serverName: serverName,
          serverType: req.body.serverType || 'PAPER'
        }
      });
      return res.redirect(303, checkoutSession.url);
    } catch (e) {
      req.flash('error', `Stripe error: ${e.message}`);
      return res.redirect('/shop');
    }
  }
  
  // Create server
  try {
    const node = db.nodes.find(n => n.id === item.nodeId) || db.nodes[0];
    if (!node) { req.flash('error', 'No available nodes.'); return res.redirect('/shop'); }
    
    const cfg = gameTypeConfig(req.body.serverType || 'PAPER');
    const port = item.port || cfg.defaultPort || 25565;
    
    const created = await callAgent(node, '/servers', { 
      method: 'POST', 
      body: { 
        name: serverName, 
        game: item.game || cfg.game, 
        image: item.image || cfg.image, 
        memoryMb: item.memoryMb, 
        cpuLimit: item.cpuLimit, 
        storageLimitMb: item.storageLimitMb, 
        ipAddress: item.ipAddress || node.publicIp || nodeHostFromUrl(node.url), 
        port, 
        storageLocation: item.storageLocation || '/var/lib/docker',
        env: { EULA: 'TRUE', TYPE: cfg.envType, VERSION: item.version || 'LATEST', MEMORY: `${Math.floor(item.memoryMb * 0.85)}M` } 
      }, 
      timeout: TIMEOUT * 60 
    });
    
    const server = { 
      id: uuidv4(), 
      agentServerId: created.server.id, 
      name: serverName, 
      game: item.game || cfg.game, 
      serverType: serverTypeKey(cfg.envType), 
      ownerId: user.id, 
      nodeId: node.id, 
      memoryMb: item.memoryMb, 
      cpuLimit: item.cpuLimit, 
      storageLimitMb: item.storageLimitMb, 
      ipAddress: item.ipAddress || node.publicIp || nodeHostFromUrl(node.url), 
      port, 
      storageLocation: item.storageLocation || '/var/lib/docker',
      subusers: [], 
      networkPorts: [], 
      databases: [], 
      subdomains: [], 
      backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, 
      createdAt: new Date().toISOString() 
    };
    
    db.servers.push(server);
    
    // Create purchase record
    const purchase = {
      id: uuidv4(),
      userId: user.id,
      itemId: item.id,
      itemName: item.name,
      serverId: server.id,
      serverName: serverName,
      price: item.price,
      paymentMethod: paymentMethod,
      status: 'active',
      createdAt: new Date().toISOString()
    };
    db.shopPurchases.push(purchase);
    
    writeDb(db);
    req.flash('success', `Server "${serverName}" purchased successfully!`);
    res.redirect(`/servers/${server.id}`);
  } catch (e) {
    // Refund if credit payment failed
    if (paymentMethod === 'credit') {
      user.creditBalance += item.price;
      user.totalSpent -= item.price;
    }
    req.flash('error', `Failed to create server: ${e.message}`);
    res.redirect('/shop');
  }
});

app.get('/shop/success', requireLogin, async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  
  try {
    const session = await stripe.checkout.sessions.retrieve(req.query.session_id);
    if (session.payment_status !== 'paid') {
      req.flash('error', 'Payment not completed.');
      return res.redirect('/shop');
    }
    
    const item = db.shopItems.find(i => i.id === session.metadata.itemId);
    if (!item) { req.flash('error', 'Item not found.'); return res.redirect('/shop'); }
    
    // Update user total spent
    user.totalSpent += item.price;
    
    // Create server (same logic as credit purchase)
    const node = db.nodes.find(n => n.id === item.nodeId) || db.nodes[0];
    if (!node) { req.flash('error', 'No available nodes.'); return res.redirect('/shop'); }
    
    const cfg = gameTypeConfig(session.metadata.serverType || 'PAPER');
    const port = item.port || cfg.defaultPort || 25565;
    
    const created = await callAgent(node, '/servers', { 
      method: 'POST', 
      body: { 
        name: session.metadata.serverName, 
        game: item.game || cfg.game, 
        image: item.image || cfg.image, 
        memoryMb: item.memoryMb, 
        cpuLimit: item.cpuLimit, 
        storageLimitMb: item.storageLimitMb, 
        ipAddress: item.ipAddress || node.publicIp || nodeHostFromUrl(node.url), 
        port, 
        storageLocation: item.storageLocation || '/var/lib/docker',
        env: { EULA: 'TRUE', TYPE: cfg.envType, VERSION: item.version || 'LATEST', MEMORY: `${Math.floor(item.memoryMb * 0.85)}M` } 
      }, 
      timeout: TIMEOUT * 60 
    });
    
    const server = { 
      id: uuidv4(), 
      agentServerId: created.server.id, 
      name: session.metadata.serverName, 
      game: item.game || cfg.game, 
      serverType: serverTypeKey(cfg.envType), 
      ownerId: user.id, 
      nodeId: node.id, 
      memoryMb: item.memoryMb, 
      cpuLimit: item.cpuLimit, 
      storageLimitMb: item.storageLimitMb, 
      ipAddress: item.ipAddress || node.publicIp || nodeHostFromUrl(node.url), 
      port, 
      storageLocation: item.storageLocation || '/var/lib/docker',
      subusers: [], 
      networkPorts: [], 
      databases: [], 
      subdomains: [], 
      backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, 
      createdAt: new Date().toISOString() 
    };
    
    db.servers.push(server);
    
    const purchase = {
      id: uuidv4(),
      userId: user.id,
      itemId: item.id,
      itemName: item.name,
      serverId: server.id,
      serverName: session.metadata.serverName,
      price: item.price,
      paymentMethod: 'stripe',
      stripePaymentId: session.payment_intent,
      status: 'active',
      createdAt: new Date().toISOString()
    };
    db.shopPurchases.push(purchase);
    
    writeDb(db);
    req.flash('success', `Server "${session.metadata.serverName}" purchased successfully!`);
    res.redirect(`/servers/${server.id}`);
  } catch (e) {
    req.flash('error', `Failed to complete purchase: ${e.message}`);
    res.redirect('/shop');
  }
});

app.post('/shop/cancel/:id', requireLogin, async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  const purchase = db.shopPurchases.find(p => p.id === req.params.id);
  
  if (!purchase || purchase.userId !== user.id) { req.flash('error', 'Purchase not found.'); return res.redirect('/shop'); }
  if (purchase.status !== 'active') { req.flash('error', 'Purchase already cancelled.'); return res.redirect('/shop'); }
  
  try {
    const server = db.servers.find(s => s.id === purchase.serverId);
    if (server) {
      const node = db.nodes.find(n => n.id === server.nodeId);
      if (node) {
        await callAgent(node, `/servers/${server.agentServerId}/delete`, { method: 'POST', timeout: TIMEOUT * 60 });
      }
      db.servers = db.servers.filter(s => s.id !== server.id);
    }
    
    purchase.status = 'cancelled';
    
    // Refund credit if paid with credit
    if (purchase.paymentMethod === 'credit') {
      user.creditBalance += purchase.price;
      user.totalSpent -= purchase.price;
    }
    
    writeDb(db);
    req.flash('success', 'Purchase cancelled and server deleted.');
    res.redirect('/shop');
  } catch (e) {
    req.flash('error', `Failed to cancel: ${e.message}`);
    res.redirect('/shop');
  }
});

app.post('/billing/subscribe', requireLogin, async (req, res) => {
  if (!STRIPE_SECRET_KEY) { req.flash('error', 'Stripe not configured.'); return res.redirect('/billing'); }
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  const plan = db.plans.find(p => p.id === req.body.planId);
  if (!plan) { req.flash('error', 'Plan not found.'); return res.redirect('/billing'); }
  try {
    const checkoutSession = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{
        price: plan.stripePriceId,
        quantity: 1,
      }],
      success_url: `${process.env.PUBLIC_BASE_URL || 'http://localhost:3000'}/billing?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.PUBLIC_BASE_URL || 'http://localhost:3000'}/billing`,
      customer_email: user.email,
      metadata: {
        userId: user.id,
        planId: plan.id,
        serverName: req.body.serverName || `${plan.name} Server`,
        serverType: req.body.serverType || 'PAPER'
      }
    });
    res.redirect(checkoutSession.url);
  } catch (e) {
    req.flash('error', `Stripe error: ${e.message}`);
    res.redirect('/billing');
  }
});

app.post('/billing/cancel/:id', requireLogin, async (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.session.userId);
  const subscription = db.subscriptions.find(s => s.id === req.params.id && s.userId === user.id);
  if (!subscription) { req.flash('error', 'Subscription not found.'); return res.redirect('/billing'); }
  try {
    if (subscription.stripeSubscriptionId && STRIPE_SECRET_KEY) {
      await stripe.subscriptions.cancel(subscription.stripeSubscriptionId);
    }
    subscription.status = 'cancelled';
    subscription.cancelledAt = new Date().toISOString();
    writeDb(db);
    
    await sendDiscordWebhook(
      'Subscription Cancelled',
      `User ${user.email} cancelled their subscription to plan ${subscription.planName}`,
      0xff0000,
      [
        { name: 'User', value: user.email },
        { name: 'Plan', value: subscription.planName },
        { name: 'Cancelled At', value: new Date().toISOString() }
      ]
    );
    
    req.flash('success', 'Subscription cancelled.');
  } catch (e) {
    req.flash('error', `Error cancelling subscription: ${e.message}`);
  }
  res.redirect('/billing');
});

app.post('/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) { return res.status(400).json({ error: 'Webhook secret not configured' }); }
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.status(400).json({ error: `Webhook signature verification failed: ${e.message}` });
  }
  const db = readDb();
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata?.userId;
    const planId = session.metadata?.planId;
    const serverName = session.metadata?.serverName || `${plan.name} Server`;
    const serverType = session.metadata?.serverType || 'PAPER';
    const node = db.nodes[0];
    const user = db.users.find(u => u.id === userId);
    const plan = db.plans.find(p => p.id === planId);
    if (user && plan && session.subscription && node) {
      const subscription = {
        id: uuidv4(),
        userId: user.id,
        planId: plan.id,
        planName: plan.name,
        stripeSubscriptionId: session.subscription,
        stripeCustomerId: session.customer,
        status: 'active',
        price: plan.price,
        interval: plan.interval,
        currency: plan.currency,
        createdAt: new Date().toISOString()
      };
      db.subscriptions.push(subscription);
      
      try {
        const template = gameTypeConfig(serverType);
        const agentServer = await callAgent(node, '/servers', { method: 'POST', timeout: TIMEOUT * 30, body: {
          name: serverName,
          image: template.image,
          env: { TYPE: template.envType, EULA: 'TRUE' },
          memoryMb: plan.memoryMb,
          cpuLimit: plan.cpuLimit,
          storageLimitMb: plan.storageLimitMb,
          port: template.defaultPort,
          storageLocation: '/var/lib/docker'
        }});
        const panelRecord = {
          id: uuidv4(),
          agentServerId: agentServer.id,
          name: serverName,
          game: template.game,
          serverType: serverType,
          image: template.image,
          ownerId: user.id,
          nodeId: node.id,
          memoryMb: plan.memoryMb,
          cpuLimit: plan.cpuLimit,
          storageLimitMb: plan.storageLimitMb,
          ipAddress: node.publicIp || nodeHostFromUrl(node.url),
          port: template.defaultPort,
          storageLocation: '/var/lib/docker',
          networkPorts: [],
          subusers: [], databases: [], subdomains: [],
          subscriptionId: subscription.id,
          createdAt: new Date().toISOString()
        };
        db.servers.push(panelRecord);
        writeDb(db);
        
        await sendDiscordWebhook(
          'New Server Created',
          `Server "${serverName}" created for ${user.email} with plan ${plan.name}`,
          0x00ff00,
          [
            { name: 'User', value: user.email },
            { name: 'Server', value: serverName },
            { name: 'Plan', value: plan.name },
            { name: 'Type', value: serverType },
            { name: 'RAM', value: `${plan.memoryMb} MB` },
            { name: 'CPU', value: plan.cpuLimit.toString() },
            { name: 'Storage', value: `${plan.storageLimitMb} MB` }
          ]
        );
      } catch (e) {
        console.error('Failed to create server after subscription:', e);
        await sendDiscordWebhook(
          'Server Creation Failed',
          `Failed to create server for ${user.email} after subscription to ${plan.name}: ${e.message}`,
          0xff0000,
          [
            { name: 'User', value: user.email },
            { name: 'Plan', value: plan.name },
            { name: 'Error', value: e.message }
          ]
        );
      }
      
      await sendDiscordWebhook(
        'New Subscription',
        `User ${user.email} subscribed to ${plan.name} ($${plan.price}/${plan.interval})`,
        0x00ff00,
        [
          { name: 'User', value: user.email },
          { name: 'Plan', value: plan.name },
          { name: 'Price', value: `$${plan.price}/${plan.interval}` },
          { name: 'Subscription ID', value: session.subscription }
        ]
      );
    }
  } else if (event.type === 'invoice.payment_succeeded') {
    const invoice = event.data.object;
    const subscription = db.subscriptions.find(s => s.stripeSubscriptionId === invoice.subscription);
    if (subscription) {
      const payment = {
        id: uuidv4(),
        userId: subscription.userId,
        subscriptionId: subscription.id,
        amount: invoice.amount_paid / 100,
        currency: invoice.currency,
        status: 'succeeded',
        stripeInvoiceId: invoice.id,
        createdAt: new Date().toISOString()
      };
      db.payments.push(payment);
      writeDb(db);
    }
  } else if (event.type === 'invoice.payment_failed') {
    const invoice = event.data.object;
    const subscription = db.subscriptions.find(s => s.stripeSubscriptionId === invoice.subscription);
    if (subscription) {
      subscription.status = 'past_due';
      writeDb(db);
    }
  } else if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const subscription = db.subscriptions.find(s => s.stripeSubscriptionId === sub.id);
    if (subscription) {
      subscription.status = 'cancelled';
      subscription.cancelledAt = new Date().toISOString();
      writeDb(db);
    }
  }
  res.json({ received: true });
});
app.post('/admin/nodes', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  db.nodes.push({
    id: uuidv4(),
    name: req.body.name,
    url: req.body.url,
    publicIp: req.body.publicIp || nodeHostFromUrl(req.body.url || ''),
    token: req.body.token || '',
    location: req.body.location || 'Unknown',
    nodeType: req.body.nodeType || 'game',
    createdAt: new Date().toISOString()
  });
  writeDb(db);
  req.flash('success', 'Node added.');
  res.redirect('/admin');
});
app.post('/admin/users', requireLogin, requireAdmin, async (req, res) => {
  const db = readDb();
  if (db.users.some(u => u.email.toLowerCase() === String(req.body.email).toLowerCase())) { req.flash('error', 'User already exists.'); return res.redirect('/admin'); }
  db.users.push({ id: uuidv4(), email: req.body.email, name: req.body.name || req.body.email, role: req.body.role || 'user', subdomainSlots: Number(req.body.subdomainSlots || 1), portSlots: Number(req.body.portSlots || 0), backupSlots: Number(req.body.backupSlots || 1), databaseSlots: Number(req.body.databaseSlots || 0), creditBalance: Number(req.body.creditBalance || 0), totalSpent: 0, passwordHash: await bcrypt.hash(req.body.password || 'ChangeMe123!', 10), subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() });
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

app.post('/admin/users/:id/credit', requireLogin, requireAdmin, (req, res) => {
  const db = readDb();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) { req.flash('error', 'User not found.'); return res.redirect('/admin#users'); }
  user.creditBalance = Math.max(0, Number(req.body.creditBalance || 0));
  writeDb(db);
  req.flash('success', 'User credit balance updated.');
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
      storageLocation: req.body.storageLocation || '/var/lib/docker',
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
    db.servers.push({ id: uuidv4(), agentServerId: created.server.id, name: req.body.name, game, serverType: serverTypeKey(cfg.envType), ownerId: owner.id, nodeId: node.id, memoryMb, cpuLimit, storageLimitMb, ipAddress, port, storageLocation: req.body.storageLocation || '/var/lib/docker', subusers: [], networkPorts: [], databases: [], subdomains: [], backupSchedule: { enabled: false, interval: 'off', keepLatest: 1, lastRunAt: null, nextRunAt: null }, createdAt: new Date().toISOString() });
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
  if (req.body.nodeType) node.nodeType = req.body.nodeType;
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
