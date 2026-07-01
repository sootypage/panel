require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const AdmZip = require('adm-zip');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 4100);
const AGENT_NAME = process.env.AGENT_NAME || 'Ubuntu Node';
const AGENT_LOCATION = process.env.AGENT_LOCATION || 'Unknown';
const AGENT_TOKEN = process.env.AGENT_TOKEN || 'change-this-agent-token';
const AGENT_ALLOWED_PANEL_IPS = String(process.env.AGENT_ALLOWED_PANEL_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
const MAX_AGENT_BODY_SIZE = process.env.MAX_AGENT_BODY_SIZE || '20mb';
const SERVERS_DIR = process.env.SERVERS_DIR || '/opt/custom-amp/servers';
const BACKUPS_DIR = process.env.BACKUPS_DIR || '/opt/custom-amp/backups';
const TMP_DIR = process.env.TMP_DIR || '/opt/custom-amp/tmp';
const DB_FILE = path.join(SERVERS_DIR, 'agent-db.json');
const MAX_CONSOLE_LINES = Number(process.env.MAX_CONSOLE_LINES || 5000);
const SFTP_PORT = Number(process.env.SFTP_PORT || process.env.FTP_PORT || 2222);
const SFTP_CONTAINER_NAME = process.env.SFTP_CONTAINER_NAME || 'custom-amp-sftp';

for (const dir of [SERVERS_DIR, BACKUPS_DIR, TMP_DIR]) fs.mkdirSync(dir, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ servers: [] }, null, 2));

const upload = multer({ dest: TMP_DIR, limits: { fileSize: 1024 * 1024 * 1024 * 5 } });
const agentLimiter = rateLimit({ windowMs: 60 * 1000, limit: 240, standardHeaders: true, legacyHeaders: false });

function readDb() { const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); db.ftpUsers = db.ftpUsers || []; return db; }
function writeDb(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function safeName(name) { return String(name || 'server').toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').slice(0, 40); }
function id() { return crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'); }
function getServer(serverId) { return readDb().servers.find(s => s.id === serverId); }
function getServerIndex(serverId) { return readDb().servers.findIndex(s => s.id === serverId); }
function serverBackupDir(server) { const dir = path.join(BACKUPS_DIR, server.id); fs.mkdirSync(dir, { recursive: true }); return dir; }
function safePath(base, requested = '') {
  const resolved = path.resolve(base, requested || '.');
  const root = path.resolve(base);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) throw new Error('Invalid path.');
  return resolved;
}
function relPath(base, target) { return path.relative(base, target).replace(/\\/g, '/'); }

function cleanConsoleLogs(logs) {
  return String(logs || '')
    .split(/\r?\n/)
    .filter(line => !line.includes('ServerMain WARN Advanced terminal features are not available in this environment'))
    .filter(line => !line.includes('Stopping with rcon-cli'))
    .filter(line => !line.includes('Failed to stop using rcon-cli'))
    .join('\n');
}

function docker(args, timeout = 120000) {
  return new Promise((resolve, reject) => {
    execFile('docker', args, { timeout, maxBuffer: 1024 * 1024 * 20 }, (error, stdout, stderr) => {
      if (error) return reject(new Error(stderr || stdout || error.message));
      resolve({ stdout, stderr });
    });
  });
}
function run(cmd, args, timeout = 300000) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout, maxBuffer: 1024 * 1024 * 20 }, (error, stdout, stderr) => {
      if (error) return reject(new Error(stderr || stdout || error.message));
      resolve({ stdout, stderr });
    });
  });
}
function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim().replace(/^::ffff:/, '');
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function auth(req, res, next) {
  const ip = clientIp(req);
  if (AGENT_ALLOWED_PANEL_IPS.length && !AGENT_ALLOWED_PANEL_IPS.includes(ip)) {
    return res.status(403).json({ error: 'Panel IP not allowed for this node.' });
  }
  const header = String(req.headers.authorization || '');
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!safeEqual(token, AGENT_TOKEN)) return res.status(401).json({ error: 'Unauthorized agent token.' });
  next();
}
async function inspectContainer(containerName) {
  try {
    const out = await docker(['inspect', containerName, '--format', '{{json .State}}']);
    return JSON.parse(out.stdout.trim());
  } catch (e) {
    return { Status: 'missing', Running: false, error: e.message };
  }
}

async function containerStats(containerName) {
  try {
    const out = await docker(['stats', '--no-stream', '--format', '{{json .}}', containerName], 30000);
    const raw = JSON.parse(out.stdout.trim());
    return {
      cpuPercent: raw.CPUPerc || '0%',
      memoryUsage: raw.MemUsage || '0B / 0B',
      memoryPercent: raw.MemPerc || '0%',
      netIO: raw.NetIO || '0B / 0B',
      blockIO: raw.BlockIO || '0B / 0B',
      pids: raw.PIDs || '0'
    };
  } catch (e) {
    return { error: e.message, cpuPercent: '0%', memoryUsage: '0B / 0B', memoryPercent: '0%' };
  }
}

function parsePercent(value) {
  const n = Number(String(value || '0').replace('%', '').trim());
  return Number.isFinite(n) ? n : 0;
}
function parseMemoryUsageBytes(value) {
  const first = String(value || '').split('/')[0].trim();
  const m = first.match(/^([0-9.]+)\s*([KMGT]?i?B|B)?$/i);
  if (!m) return 0;
  const num = Number(m[1]);
  const unit = String(m[2] || 'B').toUpperCase();
  const mult = unit.startsWith('K') ? 1024 : unit.startsWith('M') ? 1024**2 : unit.startsWith('G') ? 1024**3 : unit.startsWith('T') ? 1024**4 : 1;
  return Math.round(num * mult);
}
function resourceUpgradeHint(server, type) {
  if (type === 'storage') return `Upgrade storage above ${server.storageLimitMb || 0} MB or delete files/backups.`;
  if (type === 'memory') return `Upgrade RAM above ${server.memoryMb || 0} MB.`;
  if (type === 'cpu') return `Upgrade CPU above ${server.cpuLimit || 1} core(s) or reduce server load.`;
  return 'Upgrade this server resources.';
}
async function stopForResourceLimit(server, type, message, stats) {
  const now = new Date().toISOString();
  const db = readDb();
  const index = db.servers.findIndex(s => s.id === server.id);
  if (index === -1) return;
  const current = db.servers[index];
  current.resourceStop = {
    active: true,
    type,
    message,
    upgradeHint: resourceUpgradeHint(current, type),
    stoppedAt: now,
    stats: stats || null
  };
  current.lastStopReason = current.resourceStop.message;
  db.servers[index] = current;
  writeDb(db);
  try { await docker(['stop', current.containerName], 120000); } catch {}
}
async function enforceResourceLimits(server) {
  const state = await inspectContainer(server.containerName);
  if (!state.Running) return;
  const stats = await serverStats(server);
  const storageLimitMb = Number(server.storageLimitMb || 0);
  const usedBytes = Number(stats.storage && stats.storage.usedBytes || 0);
  const storageLimitBytes = storageLimitMb * 1024 * 1024;
  if (storageLimitBytes && usedBytes >= storageLimitBytes) {
    const usedMb = Math.ceil(usedBytes / 1024 / 1024);
    return stopForResourceLimit(server, 'storage', `Stopped because storage is full: ${usedMb} MB used of ${storageLimitMb} MB.`, stats);
  }
  const memPercent = parsePercent(stats.docker && stats.docker.memoryPercent);
  if (memPercent >= Number(process.env.RESOURCE_STOP_MEMORY_PERCENT || 99)) {
    return stopForResourceLimit(server, 'memory', `Stopped because RAM usage reached ${memPercent.toFixed(1)}% of the ${server.memoryMb || 0} MB limit.`, stats);
  }
  const cpuPercent = parsePercent(stats.docker && stats.docker.cpuPercent);
  const cpuStopPercent = Number(process.env.RESOURCE_STOP_CPU_PERCENT || 98);
  const cpuLimit = Number(server.cpuLimit || 1);
  if (cpuPercent >= cpuStopPercent * Math.max(cpuLimit, 1)) {
    return stopForResourceLimit(server, 'cpu', `Stopped because CPU usage reached ${cpuPercent.toFixed(1)}%, which is over the allowed CPU limit.`, stats);
  }
}

async function folderUsageBytes(folder) {
  try {
    const out = await run('du', ['-sb', folder], 60000);
    return Number((out.stdout || '0').split(/\s+/)[0]) || 0;
  } catch {
    return 0;
  }
}
async function diskInfo(folder) {
  try {
    const out = await run('df', ['-PB1', folder], 60000);
    const lines = out.stdout.trim().split('\n');
    const parts = lines[1].split(/\s+/);
    return { filesystem: parts[0], sizeBytes: Number(parts[1]), usedBytes: Number(parts[2]), availableBytes: Number(parts[3]), usedPercent: parts[4] };
  } catch (e) {
    return { error: e.message };
  }
}
async function serverStats(server) {
  const usageBytes = await folderUsageBytes(server.folder);
  return {
    docker: await containerStats(server.containerName),
    storage: {
      usedBytes: usageBytes,
      limitMb: Number(server.storageLimitMb || 0),
      limitBytes: Number(server.storageLimitMb || 0) * 1024 * 1024,
      disk: await diskInfo(server.folder)
    }
  };
}
async function ensureStorageAvailable(server, extraBytes = 0) {
  const limitMb = Number(server.storageLimitMb || 0);
  if (!limitMb) return;
  const used = await folderUsageBytes(server.folder);
  const limit = limitMb * 1024 * 1024;
  if (used + extraBytes > limit) throw new Error(`Storage limit exceeded. Used ${Math.ceil(used / 1024 / 1024)}MB of ${limitMb}MB.`);
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const request = client.get(url, response => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        return downloadFile(new URL(response.headers.location, url).toString(), dest).then(resolve).catch(reject);
      }
      if (response.statusCode !== 200) return reject(new Error(`Download failed with HTTP ${response.statusCode}`));
      const file = fs.createWriteStream(dest);
      response.pipe(file);
      file.on('finish', () => file.close(resolve));
      file.on('error', reject);
    });
    request.on('error', reject);
  });
}


function extractZipSafe(zipFile, destDir) {
  const zip = new AdmZip(zipFile);
  const root = path.resolve(destDir);
  fs.mkdirSync(root, { recursive: true });
  for (const entry of zip.getEntries()) {
    const target = path.resolve(root, entry.entryName);
    if (target !== root && !target.startsWith(root + path.sep)) {
      throw new Error(`Unsafe zip entry blocked: ${entry.entryName}`);
    }
  }
  zip.extractAllTo(root, true);
}
function isZipName(name) { return /\.zip$/i.test(String(name || '')); }

function defaultEnv(memoryMb, name) {
  return {
    EULA: 'TRUE',
    ENABLE_RCON: 'true',
    RCON_PASSWORD: 'minecraft',
    TYPE: 'PAPER',
    VERSION: 'LATEST',
    MEMORY: `${Math.floor(memoryMb * 0.85)}M`,
    MOTD: name || 'Minecraft Server'
  };
}
function normalizeServerEnv(server) {
  const env = Object.assign(defaultEnv(server.memoryMb, server.name), server.env || {});
  const type = String(env.TYPE || '').toUpperCase();
  if (['VELOCITY', 'BUNGEECORD', 'WATERFALL'].includes(type)) {
    // itzg/mc-proxy stores proxy files in /server internally. We bind the same host folder to /data and /server.
    delete env.EULA;
    delete env.ENABLE_RCON;
    delete env.RCON_PASSWORD;
    delete env.MOTD;
  }
  if (type === 'CUSTOM') {
    env.CUSTOM_SERVER = env.CUSTOM_SERVER || '/data/server.jar';
    env.TYPE = 'CUSTOM';
  }
  if (isRustServer(server)) {
    // Common Rust image vars; users can edit/add more in future.
    delete env.EULA;
    delete env.ENABLE_RCON;
    delete env.RCON_PASSWORD;
    env.RUST_SERVER_NAME = env.RUST_SERVER_NAME || server.name || 'Rust Server';
  }
  if (isTerrariaServer(server) || isValheimServer(server) || isFactorioServer(server)) {
    delete env.EULA;
    delete env.ENABLE_RCON;
    delete env.RCON_PASSWORD;
    delete env.TYPE;
    delete env.MEMORY;
    delete env.MOTD;
    if (isValheimServer(server)) {
      env.SERVER_NAME = env.SERVER_NAME || server.name || 'Valheim Server';
      env.WORLD_NAME = env.WORLD_NAME || 'Dedicated';
      env.SERVER_PASS = env.SERVER_PASS || crypto.randomBytes(5).toString('hex');
    }
  }
  return env;
}
function isProxyServer(server) {
  const type = String((server.env && server.env.TYPE) || '').toUpperCase();
  const image = String(server.image || '').toLowerCase();
  const game = String(server.game || '').toLowerCase();
  return ['VELOCITY', 'BUNGEECORD', 'WATERFALL'].includes(type) || image.includes('mc-proxy') || game.includes('velocity') || game.includes('bungeecord') || game.includes('waterfall');
}
function isRustServer(server) {
  const image = String(server.image || '').toLowerCase();
  const game = String(server.game || '').toLowerCase();
  return game === 'rust' || game.includes('rust') || image.includes('rust');
}
function isTerrariaServer(server) {
  const image = String(server.image || '').toLowerCase();
  const game = String(server.game || '').toLowerCase();
  return game.includes('terraria') || image.includes('terraria');
}
function isValheimServer(server) {
  const image = String(server.image || '').toLowerCase();
  const game = String(server.game || '').toLowerCase();
  return game.includes('valheim') || image.includes('valheim');
}
function isFactorioServer(server) {
  const image = String(server.image || '').toLowerCase();
  const game = String(server.game || '').toLowerCase();
  return game.includes('factorio') || image.includes('factorio');
}
function mainContainerPort(server) {
  if (isProxyServer(server)) return 25577;
  if (isRustServer(server)) return 28015;
  if (isTerrariaServer(server)) return 7777;
  if (isValheimServer(server)) return 2456;
  if (isFactorioServer(server)) return 34197;
  return 25565;
}
function buildDockerArgs(server) {
  const env = normalizeServerEnv(server);
  env.MEMORY = env.MEMORY || `${Math.floor(Number(server.memoryMb || 2048) * 0.85)}M`;
  const args = ['run', '-d', '--name', server.containerName, '--restart', 'unless-stopped', '-m', `${server.memoryMb}m`, '--cpus', String(server.cpuLimit || 1), '-v', `${server.folder}:/data`];
  if (isProxyServer(server)) args.push('-v', `${server.folder}:/server`);
  if (isRustServer(server)) args.push('-v', `${server.folder}:/steamcmd/rust`);
  if (isTerrariaServer(server)) args.push('-v', `${server.folder}:/root/.local/share/Terraria/Worlds`);
  if (isValheimServer(server)) args.push('-v', `${server.folder}:/config`);
  if (isFactorioServer(server)) args.push('-v', `${server.folder}:/factorio`);

  const usedBindings = new Set();
  function addBinding(publicPort, containerPort, protocol = 'tcp') {
    publicPort = Number(publicPort); containerPort = Number(containerPort); protocol = String(protocol || 'tcp').toLowerCase();
    if (!publicPort || !containerPort) return;
    const key = `${publicPort}:${containerPort}/${protocol}`;
    if (usedBindings.has(key)) return;
    usedBindings.add(key);
    args.push('-p', `${publicPort}:${containerPort}/${protocol}`);
  }

  const mainPort = mainContainerPort(server);
  if (isRustServer(server)) {
    addBinding(server.port || 28015, 28015, 'udp');
    addBinding(server.port || 28015, 28015, 'tcp');
  } else if (isValheimServer(server)) {
    addBinding(server.port || 2456, 2456, 'udp');
    addBinding(Number(server.port || 2456) + 1, 2457, 'udp');
    addBinding(Number(server.port || 2456) + 2, 2458, 'udp');
  } else if (isFactorioServer(server)) {
    addBinding(server.port || 34197, 34197, 'udp');
  } else {
    addBinding(server.port || mainPort, mainPort, 'tcp');
  }

  for (const p of (server.networkPorts || [])) {
    addBinding(p.publicPort || p.port, p.containerPort || p.port, p.protocol || p.type || 'tcp');
  }

  for (const [key, value] of Object.entries(env)) args.push('-e', `${key}=${String(value)}`);
  args.push(server.image || (isRustServer(server) ? 'didstopia/rust-server:latest' : isProxyServer(server) ? 'itzg/mc-proxy' : 'itzg/minecraft-server:java21'));
  return args;
}
async function removeContainer(name) {
  try { await docker(['rm', '-f', name], 60000); } catch (e) {}
  // Also try to disconnect from bridge network to clean up stale endpoints
  try { await docker(['network', 'disconnect', 'bridge', name], 30000); } catch (e) {}
}
async function recreateContainer(server) {
  await removeContainer(server.containerName);
  await docker(buildDockerArgs(server), 180000);
}

function propertiesPath(server) { return path.join(server.folder, 'server.properties'); }
function readProperties(server) {
  const file = propertiesPath(server);
  const props = {};
  if (!fs.existsSync(file)) return props;
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    if (!line || line.startsWith('#') || !line.includes('=')) continue;
    const index = line.indexOf('=');
    const key = line.slice(0, index).trim();
    const value = line.slice(index + 1);
    props[key] = value;
  }
  return props;
}
function writeProperties(server, changes) {
  const file = propertiesPath(server);
  const props = readProperties(server);
  for (const [k, v] of Object.entries(changes)) {
    if (v === undefined || v === null || v === '') continue;
    props[k] = String(v);
  }
  const lines = Object.keys(props).sort().map(key => `${key}=${props[key]}`);
  fs.writeFileSync(file, lines.join('\n') + '\n');
}
function serverSettings(server) {
  const props = readProperties(server);
  const env = Object.assign(defaultEnv(server.memoryMb, server.name), server.env || {});
  return {
    type: env.TYPE || 'PAPER',
    version: env.VERSION || 'LATEST',
    motd: props.motd || env.MOTD || server.name,
    seed: props['level-seed'] || '',
    levelType: props['level-type'] || 'minecraft\:normal',
    difficulty: props.difficulty || 'easy',
    gameMode: props.gamemode || 'survival',
    maxPlayers: props['max-players'] || '20',
    onlineMode: String(props['online-mode'] || 'true'),
    pvp: String(props.pvp || 'true'),
    allowFlight: String(props['allow-flight'] || 'false'),
    spawnProtection: props['spawn-protection'] || '16',
    viewDistance: props['view-distance'] || '10',
    simulationDistance: props['simulation-distance'] || '10'
  };
}

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, referrerPolicy: { policy: 'same-origin' } }));
app.use(agentLimiter);
app.use(morgan('dev'));
app.use(express.json({ limit: MAX_AGENT_BODY_SIZE }));
app.use(express.urlencoded({ extended: true, limit: MAX_AGENT_BODY_SIZE }));

app.get('/health', auth, async (req, res) => {
  let dockerOk = true;
  let dockerVersion = 'unknown';
  try { dockerVersion = (await docker(['--version'])).stdout.trim(); } catch (e) { dockerOk = false; }
  res.json({ ok: true, name: AGENT_NAME, location: AGENT_LOCATION, dockerOk, dockerVersion, time: new Date().toISOString() });
});

app.get('/servers/:serverId/stats', auth, async (req, res) => {
  const server = getServer(req.params.serverId);
  if (!server) return res.status(404).json({ error: 'Server not found' });
  
  try {
    const containerName = server.containerName;
    
    // Get container stats - try JSON format first, fallback to no format
    let stats;
    try {
      stats = await docker(['stats', '--no-stream', '--format', 'json', containerName]);
    } catch (e) {
      // Fallback for older Docker versions without --format json
      stats = await docker(['stats', '--no-stream', containerName]);
    }
    
    const statsData = JSON.parse(stats.stdout);
    
    if (statsData && statsData.length > 0) {
      const s = statsData[0];
      const cpuPercent = s.CPUPerc ? parseFloat(s.CPUPerc) : 0;
      const memUsage = s.MemUsage ? s.MemUsage.split(' / ')[0] : '0B';
      const memPercent = s.MemPerc ? parseFloat(s.MemPerc) : 0;
      const netRx = s.NetIO ? s.NetIO.split(' / ')[0] : '0B';
      const netTx = s.NetIO ? s.NetIO.split(' / ')[1] : '0B';
      const blockRead = s.BlockIO ? s.BlockIO.split(' / ')[0] : '0B';
      const blockWrite = s.BlockIO ? s.BlockIO.split(' / ')[1] : '0B';
      
      res.json({
        ok: true,
        cpu: cpuPercent,
        memory: {
          usage: memUsage,
          percent: memPercent
        },
        network: {
          rx: netRx,
          tx: netTx
        },
        disk: {
          read: blockRead,
          write: blockWrite
        }
      });
    } else {
      res.json({ ok: true, cpu: 0, memory: { usage: '0B', percent: 0 }, network: { rx: '0B', tx: '0B' }, disk: { read: '0B', write: '0B' } });
    }
  } catch (e) {
    res.json({ ok: true, cpu: 0, memory: { usage: '0B', percent: 0 }, network: { rx: '0B', tx: '0B' }, disk: { read: '0B', write: '0B' }, error: e.message });
  }
});

app.get('/storage-locations', auth, async (req, res) => {
  const commonLocations = [
    '/var/lib/docker',
    '/mnt/ssd1',
    '/mnt/ssd2',
    '/mnt/ssd3',
    '/mnt/nvme0n1',
    '/mnt/nvme0n2',
    '/mnt/hdd1',
    '/mnt/hdd2',
    '/home/docker',
    '/opt/docker'
  ];
  
  const availableLocations = [];
  
  for (const loc of commonLocations) {
    try {
      if (fs.existsSync(loc)) {
        const stats = fs.statSync(loc);
        if (stats.isDirectory()) {
          availableLocations.push(loc);
        }
      }
    } catch (e) {
      // Location doesn't exist or isn't accessible, skip it
    }
  }
  
  // Always include the default SERVERS_DIR if it's not already in the list
  if (availableLocations.length === 0 || !availableLocations.includes(SERVERS_DIR)) {
    try {
      if (fs.existsSync(SERVERS_DIR)) {
        availableLocations.push(SERVERS_DIR);
      }
    } catch (e) {
      // SERVERS_DIR doesn't exist, skip
    }
  }
  
  // If no locations found, return a default
  if (availableLocations.length === 0) {
    availableLocations.push('/var/lib/docker');
  }
  
  res.json({ ok: true, locations: availableLocations });
});

app.post('/servers', auth, async (req, res) => {
  const db = readDb();
  const serverId = id();
  const name = req.body.name || `server-${serverId.slice(0, 8)}`;
  const folder = path.join(SERVERS_DIR, `${safeName(name)}-${serverId.slice(0, 8)}`);
  fs.mkdirSync(folder, { recursive: true });

  const image = req.body.image || 'itzg/minecraft-server:java21';
  const port = Number(req.body.port || 25565);
  const memoryMb = Number(req.body.memoryMb || 2048);
  const cpuLimit = Number(req.body.cpuLimit || 1);
  const storageLimitMb = Number(req.body.storageLimitMb || 10240);
  const ipAddress = req.body.ipAddress || '';
  const containerName = `amp-${safeName(name)}-${serverId.slice(0, 8)}`;
  const env = Object.assign(defaultEnv(memoryMb, name), req.body.env || {});

  const server = { id: serverId, name, image, port, ipAddress, memoryMb, cpuLimit, storageLimitMb, containerName, folder, env, networkPorts: req.body.networkPorts || [], game: req.body.game || 'minecraft-paper', resourceStop: null, createdAt: new Date().toISOString() };

  try {
    await docker(buildDockerArgs(server));
    db.servers.push(server);
    writeDb(db);
    res.json({ ok: true, server });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/servers', auth, async (req, res) => {
  const db = readDb();
  const servers = [];
  for (const server of db.servers) servers.push(Object.assign({}, server, { state: await inspectContainer(server.containerName), stats: await serverStats(server) }));
  res.json({ servers });
});

app.get('/servers/:id', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const state = await inspectContainer(server.containerName);
  if (state && state.OOMKilled && !(server.resourceStop && server.resourceStop.active)) {
    await stopForResourceLimit(server, 'memory', `Stopped because the server ran out of RAM and Docker killed it. Current RAM limit is ${server.memoryMb || 0} MB.`, await serverStats(server));
  }
  const latestServer = getServer(req.params.id) || server;
  let logs = '';
  try {
    const out = await docker(['logs', '--tail', String(MAX_CONSOLE_LINES), latestServer.containerName]);
    logs = cleanConsoleLogs(`${out.stdout || ''}${out.stderr || ''}`);
  } catch (e) { logs = e.message; }
  res.json({ server: latestServer, state, stats: await serverStats(latestServer), settings: serverSettings(latestServer), logs });
});

app.get('/servers/:id/logs', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const lines = Math.min(Number(req.query.lines || MAX_CONSOLE_LINES), 50000);
  try {
    const out = await docker(['logs', '--tail', String(lines), server.containerName]);
    res.json({ logs: cleanConsoleLogs(`${out.stdout || ''}${out.stderr || ''}`) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/servers/:id/stats', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try {
    const state = await inspectContainer(server.containerName);
    if (state && state.OOMKilled && !(server.resourceStop && server.resourceStop.active)) {
      await stopForResourceLimit(server, 'memory', `Stopped because the server ran out of RAM and Docker killed it. Current RAM limit is ${server.memoryMb || 0} MB.`, await serverStats(server));
    }
    const latestServer = getServer(req.params.id) || server;
    res.json({ stats: await serverStats(latestServer), state, server: latestServer });
  }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/servers/:id/start', auth, async (req, res) => {
  const db = readDb();
  const index = db.servers.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Server not found.' });
  const server = db.servers[index];
  server.resourceStop = null;
  server.lastStopReason = null;
  db.servers[index] = server;
  writeDb(db);
  try { await docker(['start', server.containerName]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/servers/:id/stop', auth, async (req, res) => {
  const db = readDb();
  const index = db.servers.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Server not found.' });
  const server = db.servers[index];
  server.lastStopReason = req.body && req.body.reason ? String(req.body.reason).slice(0, 300) : 'Stopped manually from the panel.';
  db.servers[index] = server;
  writeDb(db);
  try { await docker(['stop', server.containerName]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/servers/:id/restart', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try { await docker(['restart', server.containerName]); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/servers/:id/command', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const command = String(req.body.command || '').trim();
  if (!command) return res.status(400).json({ error: 'Command is required.' });
  try { await docker(['exec', server.containerName, 'rcon-cli', command]); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message + ' Make sure RCON is enabled.' }); }
});

app.get('/servers/:id/settings', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  res.json({ settings: serverSettings(server), server });
});
app.post('/servers/:id/settings', auth, async (req, res) => {
  const db = readDb();
  const index = db.servers.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Server not found.' });
  const server = db.servers[index];
  const currentVersion = (server.env && server.env.VERSION) || 'LATEST';
  const nextVersion = String(req.body.version || currentVersion).trim() || currentVersion;
  const currentType = String((server.env && server.env.TYPE) || 'PAPER').toUpperCase();
  const nextType = String(req.body.serverType || req.body.type || currentType).toUpperCase();

  server.env = Object.assign(defaultEnv(server.memoryMb, server.name), server.env || {});
  server.env.VERSION = nextVersion;
  server.env.TYPE = nextType;
  if (req.body.motd !== undefined) server.env.MOTD = String(req.body.motd || server.name);
  if (req.body.customServerJar !== undefined && String(req.body.customServerJar || '').trim()) server.env.CUSTOM_SERVER = String(req.body.customServerJar).trim().startsWith('/') ? String(req.body.customServerJar).trim() : `/data/${String(req.body.customServerJar).trim()}`;
  const typeMap = {
    PAPER: { game: 'minecraft-paper', image: 'itzg/minecraft-server:java21' },
    PURPUR: { game: 'minecraft-purpur', image: 'itzg/minecraft-server:java21' },
    FABRIC: { game: 'minecraft-fabric', image: 'itzg/minecraft-server:java21' },
    FORGE: { game: 'minecraft-forge', image: 'itzg/minecraft-server:java21' },
    NEOFORGE: { game: 'minecraft-neoforge', image: 'itzg/minecraft-server:java21' },
    VANILLA: { game: 'minecraft-vanilla', image: 'itzg/minecraft-server:java21' },
    VELOCITY: { game: 'minecraft-velocity', image: 'itzg/mc-proxy' },
    BUNGEECORD: { game: 'minecraft-bungeecord', image: 'itzg/mc-proxy' },
    WATERFALL: { game: 'minecraft-waterfall', image: 'itzg/mc-proxy' },
    RUST: { game: 'rust', image: 'didstopia/rust-server:latest' },
    CUSTOM: { game: 'minecraft-custom-jar', image: 'itzg/minecraft-server:java21' },
    CUSTOM: { game: 'minecraft-custom-jar', image: 'itzg/minecraft-server:java21' }
  };
  if (typeMap[nextType]) { server.game = typeMap[nextType].game; server.image = typeMap[nextType].image; }
  writeProperties(server, {
    motd: req.body.motd,
    'level-seed': req.body.seed,
    'level-type': req.body.levelType,
    difficulty: req.body.difficulty,
    gamemode: req.body.gameMode,
    'max-players': req.body.maxPlayers,
    'online-mode': req.body.onlineMode,
    pvp: req.body.pvp,
    'allow-flight': req.body.allowFlight,
    'spawn-protection': req.body.spawnProtection,
    'view-distance': req.body.viewDistance,
    'simulation-distance': req.body.simulationDistance
  });
  db.servers[index] = server;
  writeDb(db);

  try {
    if (nextVersion !== currentVersion || nextType !== currentType) await recreateContainer(server);
    res.json({ ok: true, settings: serverSettings(server), recreated: nextVersion !== currentVersion || nextType !== currentType });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/servers/:id/files', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try {
    const dir = safePath(server.folder, req.query.path || '');
    const items = fs.readdirSync(dir, { withFileTypes: true }).map(d => {
      const full = path.join(dir, d.name);
      const stat = fs.statSync(full);
      return { name: d.name, path: relPath(server.folder, full), type: d.isDirectory() ? 'dir' : 'file', size: stat.size, modifiedAt: stat.mtime.toISOString() };
    }).sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === 'dir' ? -1 : 1));
    const rel = relPath(server.folder, dir);
    res.json({ path: rel === '.' ? '' : rel, parent: relPath(server.folder, path.dirname(dir)) === '.' ? '' : relPath(server.folder, path.dirname(dir)), items });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/servers/:id/files/download', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try {
    const file = safePath(server.folder, req.query.path || '');
    if (!fs.existsSync(file)) return res.status(400).json({ error: 'File not found.' });
    const stat = fs.statSync(file);
    if (stat.isDirectory()) {
      const baseName = path.basename(file) || 'server-files';
      const tmp = path.join(TMP_DIR, `${safeName(baseName)}-${Date.now()}.tar.gz`);
      await run('tar', ['-czf', tmp, '-C', file, '.'], 300000);
      return res.download(tmp, `${baseName}.tar.gz`, () => fs.rmSync(tmp, { force: true }));
    }
    res.download(file);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/servers/:id/files/upload', auth, upload.array('files', 50), async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const uploaded = req.files || [];
  try {
    const total = uploaded.reduce((sum, f) => sum + (f.size || 0), 0);
    await ensureStorageAvailable(server, total);
    const dir = safePath(server.folder, req.body.path || '');
    fs.mkdirSync(dir, { recursive: true });
    const results = [];
    for (const file of uploaded) {
      const dest = safePath(dir, file.originalname);
      fs.renameSync(file.path, dest);
      if (String(req.body.extractZip || '').toLowerCase() === 'true' && isZipName(file.originalname)) {
        extractZipSafe(dest, dir);
        if (String(req.body.deleteZipAfterExtract || '').toLowerCase() === 'true') fs.rmSync(dest, { force: true });
        results.push({ path: relPath(server.folder, dest), extracted: true });
      } else {
        results.push({ path: relPath(server.folder, dest), extracted: false });
      }
    }
    res.json({ ok: true, files: results });
  } catch (e) { for (const file of uploaded) fs.rmSync(file.path, { force: true }); res.status(400).json({ error: e.message }); }
});

app.post('/servers/:id/files/unzip', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try {
    const zipFile = safePath(server.folder, req.body.path || '');
    if (!fs.existsSync(zipFile) || !isZipName(zipFile)) return res.status(400).json({ error: 'Pick a .zip file to unzip.' });
    const destDir = safePath(server.folder, req.body.destination || path.dirname(req.body.path || ''));
    extractZipSafe(zipFile, destDir);
    res.json({ ok: true, extractedTo: relPath(server.folder, destDir) });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/servers/:id/files/mkdir', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try { fs.mkdirSync(safePath(server.folder, path.join(req.body.path || '', req.body.name || 'new-folder')), { recursive: true }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/servers/:id/files/delete', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try { fs.rmSync(safePath(server.folder, req.body.path || ''), { recursive: true, force: true }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.get('/servers/:id/files/edit', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try {
    const file = safePath(server.folder, req.query.path || '');
    if (fs.statSync(file).size > 1024 * 1024 * 2) return res.status(400).json({ error: 'File is too large to edit in browser.' });
    res.json({ path: relPath(server.folder, file), content: fs.readFileSync(file, 'utf8') });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/servers/:id/files/edit', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try { fs.writeFileSync(safePath(server.folder, req.body.path || ''), String(req.body.content || '')); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/servers/:id/backups', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const dir = serverBackupDir(server);
  const backups = fs.readdirSync(dir).filter(f => f.endsWith('.tar.gz')).map(name => {
    const stat = fs.statSync(path.join(dir, name));
    return { name, size: stat.size, createdAt: stat.mtime.toISOString() };
  }).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({ backups });
});
app.post('/servers/:id/backups', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const name = `${safeName(server.name)}-${new Date().toISOString().replace(/[:.]/g, '-')}.tar.gz`;
  const backupPath = path.join(serverBackupDir(server), name);
  try { await run('tar', ['-czf', backupPath, '-C', server.folder, '.']); res.json({ ok: true, backup: { name } }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/servers/:id/backups/:name', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const file = safePath(serverBackupDir(server), req.params.name);
  if (!file.endsWith('.tar.gz')) return res.status(400).json({ error: 'Invalid backup.' });
  res.download(file);
});
app.post('/servers/:id/backups/delete', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try { fs.rmSync(safePath(serverBackupDir(server), req.body.name || ''), { force: true }); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});


app.post('/servers/:id/saves/upload', auth, upload.single('save'), async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  if (!req.file) return res.status(400).json({ error: 'Save file is required.' });
  const worldName = safeName(req.body.worldName || 'world') || 'world';
  const mode = req.body.mode === 'replace' ? 'replace' : 'new';
  const target = safePath(server.folder, worldName);
  const work = path.join(TMP_DIR, `save-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  try {
    await ensureStorageAvailable(server, req.file.size);
    fs.mkdirSync(work, { recursive: true });
    const original = req.file.originalname.toLowerCase();
    if (original.endsWith('.zip')) {
      await run('unzip', ['-q', req.file.path, '-d', work], 300000);
    } else if (original.endsWith('.tar.gz') || original.endsWith('.tgz')) {
      await run('tar', ['-xzf', req.file.path, '-C', work], 300000);
    } else {
      throw new Error('Upload a .zip, .tar.gz, or .tgz world/save archive.');
    }
    if (mode === 'replace' && fs.existsSync(target)) fs.rmSync(target, { recursive: true, force: true });
    fs.mkdirSync(target, { recursive: true });
    const children = fs.readdirSync(work);
    let source = work;
    if (children.length === 1 && fs.statSync(path.join(work, children[0])).isDirectory()) source = path.join(work, children[0]);
    for (const name of fs.readdirSync(source)) {
      fs.cpSync(path.join(source, name), path.join(target, name), { recursive: true });
    }
    res.json({ ok: true, world: worldName, path: relPath(server.folder, target) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  } finally {
    fs.rmSync(req.file.path, { force: true });
    fs.rmSync(work, { recursive: true, force: true });
  }
});

app.post('/servers/:id/installer', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const type = req.body.type === 'mod' ? 'mods' : 'plugins';
  const url = String(req.body.url || '').trim();
  if (!/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'Plugin/mod URL must start with http:// or https://.' });
  try {
    const parsed = new URL(url);
    const filename = path.basename(parsed.pathname) || `download-${Date.now()}.jar`;
    await ensureStorageAvailable(server, 1024 * 1024 * 200);
    const dir = safePath(server.folder, type);
    fs.mkdirSync(dir, { recursive: true });
    const dest = safePath(dir, filename);
    await downloadFile(url, dest);
    res.json({ ok: true, installedTo: relPath(server.folder, dest) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});


app.get('/servers/:id/properties', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try {
    const file = propertiesPath(server);
    const content = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    res.json({ content });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/servers/:id/properties', auth, (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  try {
    fs.writeFileSync(propertiesPath(server), String(req.body.content || ''));
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/servers/:id/backups/restore', auth, async (req, res) => {
  const server = getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const name = String(req.body.name || '');
  if (!name.endsWith('.tar.gz')) return res.status(400).json({ error: 'Invalid backup name.' });
  const backup = safePath(serverBackupDir(server), name);
  if (!fs.existsSync(backup)) return res.status(404).json({ error: 'Backup not found.' });

  try {
    const state = await inspectContainer(server.containerName);
    const wasRunning = !!state.Running;
    if (wasRunning) {
      try { await docker(['stop', server.containerName], 120000); } catch {}
    }

    fs.mkdirSync(server.folder, { recursive: true });
    for (const item of fs.readdirSync(server.folder)) {
      fs.rmSync(path.join(server.folder, item), { recursive: true, force: true });
    }

    await run('tar', ['-xzf', backup, '-C', server.folder], 300000);

    if (wasRunning) {
      try { await docker(['start', server.containerName], 120000); } catch {}
    }

    res.json({ ok: true, restored: name, restarted: wasRunning });
  } catch (e) { res.status(500).json({ error: e.message }); }
});




app.get('/docker/containers', auth, async (req, res) => {
  try {
    const db = readDb();
    const out = await docker(['ps', '-a', '--format', '{{json .}}'], 60000);
    const rows = out.stdout.trim() ? out.stdout.trim().split('\n').map(line => JSON.parse(line)) : [];
    const containers = [];
    for (const row of rows) {
      let inspect = null;
      try { inspect = JSON.parse((await docker(['inspect', row.ID], 60000)).stdout)[0]; } catch {}
      const mounts = (inspect && inspect.Mounts ? inspect.Mounts : []).map(m => ({ source: m.Source, destination: m.Destination }));
      const dataMount = mounts.find(m => ['/data','/server','/config','/factorio','/steamcmd/rust','/root/.local/share/Terraria/Worlds'].includes(m.destination)) || mounts[0];
      const ports = [];
      const rawPorts = inspect && inspect.NetworkSettings && inspect.NetworkSettings.Ports ? inspect.NetworkSettings.Ports : {};
      for (const [containerPort, bindings] of Object.entries(rawPorts)) {
        if (bindings) for (const b of bindings) ports.push({ publicPort: Number(b.HostPort), containerPort: Number(containerPort.split('/')[0]), protocol: containerPort.split('/')[1] || 'tcp' });
      }
      containers.push({
        id: row.ID,
        name: row.Names,
        image: row.Image,
        status: row.Status,
        state: row.State,
        ports,
        mounts,
        dataPath: dataMount ? dataMount.source : '',
        canImport: !!dataMount,
        imported: db.servers.some(s => s.containerName === row.Names || s.containerId === row.ID || s.folder === (dataMount ? dataMount.source : ''))
      });
    }
    res.json({ containers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/docker/import', auth, async (req, res) => {
  try {
    const containerRef = req.body.container || req.body.containerId || req.body.name;
    if (!containerRef) return res.status(400).json({ error: 'Container is required.' });
    const inspect = JSON.parse((await docker(['inspect', containerRef], 60000)).stdout)[0];
    const containerName = String(inspect.Name || '').replace(/^\//, '');
    const preferredMounts = ['/data', '/server', '/config', '/factorio', '/steamcmd/rust', '/root/.local/share/Terraria/Worlds'];
    const dataMount = (inspect.Mounts || []).find(m => preferredMounts.includes(m.Destination)) || (inspect.Mounts || [])[0];
    if (!dataMount) return res.status(400).json({ error: 'Cannot import: no usable bind mount/volume found.' });
    const rawPorts = inspect.NetworkSettings && inspect.NetworkSettings.Ports ? inspect.NetworkSettings.Ports : {};
    function findPort(containerPort, proto='tcp') { const b = rawPorts[`${containerPort}/${proto}`]; return b && b[0] ? Number(b[0].HostPort) : null; }
    const publicPort = Number(req.body.port || findPort(25565, 'tcp') || findPort(25577, 'tcp') || findPort(28015, 'tcp') || 25565);
    const networkPorts = [];
    for (const [containerPort, bindings] of Object.entries(rawPorts)) {
      if (!bindings) continue;
      for (const b of bindings) {
        const cPort = Number(containerPort.split('/')[0]);
        const proto = containerPort.split('/')[1] || 'tcp';
        const pPort = Number(b.HostPort);
        if (pPort !== publicPort) networkPorts.push({ publicPort: pPort, containerPort: cPort, protocol: proto, name: `${proto.toUpperCase()} ${pPort}` });
      }
    }
    const env = {};
    for (const item of (inspect.Config.Env || [])) { const i = item.indexOf('='); if (i > -1) env[item.slice(0, i)] = item.slice(i + 1); }
    const image = inspect.Config.Image || req.body.image || 'itzg/minecraft-server:java21';
    const serverType = String(req.body.serverType || env.TYPE || (image.includes('mc-proxy') ? 'VELOCITY' : 'PAPER')).toUpperCase();
    const server = {
      id: req.body.id || id(),
      name: req.body.name || containerName.replace(/^amp-/, ''),
      image,
      port: publicPort,
      ipAddress: req.body.ipAddress || '',
      memoryMb: Number(req.body.memoryMb || String(env.MEMORY || '').replace(/[^0-9]/g, '') || 2048),
      cpuLimit: Number(req.body.cpuLimit || 1),
      storageLimitMb: Number(req.body.storageLimitMb || 10240),
      containerName,
      containerId: inspect.Id,
      folder: dataMount.Source,
      env: Object.assign({}, env, { TYPE: serverType, VERSION: env.VERSION || req.body.version || 'LATEST' }),
      networkPorts,
      game: req.body.game || (serverType === 'RUST' ? 'rust' : `minecraft-${serverType.toLowerCase()}`),
      imported: true,
      createdAt: new Date().toISOString()
    };
    const db = readDb();
    const existing = db.servers.find(s => s.containerName === containerName || s.containerId === inspect.Id || s.folder === server.folder);
    if (existing) Object.assign(existing, server, { id: existing.id }); else db.servers.push(server);
    if (req.body.recreateManaged === true || req.body.recreateManaged === 'true' || req.body.recreateManaged === 'on') {
      await recreateContainer(existing || server);
    }
    writeDb(db);
    res.json({ ok: true, server: existing || server, recreated: !!req.body.recreateManaged });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/servers/:id/resources', auth, async (req, res) => {
  const db = readDb();
  const index = db.servers.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Server not found.' });
  const server = db.servers[index];
  server.memoryMb = Number(req.body.memoryMb || server.memoryMb || 2048);
  server.cpuLimit = Number(req.body.cpuLimit || server.cpuLimit || 1);
  server.storageLimitMb = Number(req.body.storageLimitMb || server.storageLimitMb || 10240);
  server.resourceStop = null;
  server.lastStopReason = null;
  if (req.body.port) server.port = Number(req.body.port);
  if (Array.isArray(req.body.networkPorts)) {
    server.networkPorts = req.body.networkPorts.map(p => ({
      port: Number(p.port || p.publicPort),
      publicPort: Number(p.publicPort || p.port),
      containerPort: Number(p.containerPort || p.port || p.publicPort),
      type: p.type || p.protocol || 'tcp',
      protocol: p.protocol || p.type || 'tcp',
      notes: p.notes || ''
    })).filter(p => p.publicPort && p.containerPort);
  }
  db.servers[index] = server;
  writeDb(db);
  try { await recreateContainer(server); res.json({ ok: true, server, recreated: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/servers/:id/delete', auth, async (req, res) => {
  const db = readDb();
  const index = db.servers.findIndex(s => s.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Server not found.' });
  const server = db.servers[index];
  try { await docker(['rm', '-f', server.containerName], 120000); } catch {}
  try { await docker(['network', 'disconnect', 'bridge', server.containerName], 30000); } catch {}
  try { if (server.folder) fs.rmSync(server.folder, { recursive: true, force: true }); } catch {}
  try { fs.rmSync(serverBackupDir(server), { recursive: true, force: true }); } catch {}
  db.servers.splice(index, 1);
  writeDb(db);
  res.json({ ok: true, deleted: server.id });
});


function makeFtpUsername(server) {
  return `srv_${safeName(server.name).replace(/-/g, '_')}_${String(server.id).slice(0, 8)}`.slice(0, 32);
}
function makeFtpPassword() {
  return crypto.randomBytes(12).toString('hex');
}
async function recreateSftpContainer() {
  const db = readDb();
  const ftpUsers = db.ftpUsers || [];
  try { await docker(['rm', '-f', SFTP_CONTAINER_NAME], 60000); } catch {}
  if (!ftpUsers.length) return { ok: true, running: false, users: 0 };
  const args = ['run', '-d', '--name', SFTP_CONTAINER_NAME, '--restart', 'unless-stopped', '-p', `${SFTP_PORT}:22/tcp`];
  const commandUsers = [];
  for (const user of ftpUsers) {
    const server = db.servers.find(s => s.id === user.serverId);
    if (!server || !server.folder || !fs.existsSync(server.folder)) continue;
    args.push('-v', `${server.folder}:/home/${user.username}/server`);
    // atmoz/sftp format: user:pass:uid:gid:dirs
    commandUsers.push(`${user.username}:${user.password}:1000:1000:server`);
  }
  if (!commandUsers.length) return { ok: true, running: false, users: 0 };
  args.push('atmoz/sftp:latest', ...commandUsers);
  await docker(args, 120000);
  return { ok: true, running: true, users: commandUsers.length, port: SFTP_PORT };
}

app.get('/servers/:id/ftp', auth, async (req, res) => {
  const db = readDb();
  const server = db.servers.find(s => s.id === req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  const user = (db.ftpUsers || []).find(u => u.serverId === server.id);
  res.json({
    enabled: !!user,
    host: req.hostname,
    port: SFTP_PORT,
    protocol: 'SFTP',
    username: user ? user.username : '',
    password: user ? user.password : '',
    note: 'Use SFTP, not plain FTP. The user is restricted to this server folder.'
  });
});

app.post('/servers/:id/ftp/reset', auth, async (req, res) => {
  const db = readDb();
  const server = db.servers.find(s => s.id === req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  db.ftpUsers = db.ftpUsers || [];
  db.ftpUsers = db.ftpUsers.filter(u => u.serverId !== server.id);
  const ftpUser = {
    id: id(),
    serverId: server.id,
    username: makeFtpUsername(server),
    password: makeFtpPassword(),
    createdAt: new Date().toISOString()
  };
  db.ftpUsers.push(ftpUser);
  writeDb(db);
  try {
    const status = await recreateSftpContainer();
    res.json({ ok: true, ftp: { enabled: true, protocol: 'SFTP', port: SFTP_PORT, username: ftpUser.username, password: ftpUser.password }, status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/servers/:id/ftp/disable', auth, async (req, res) => {
  const db = readDb();
  const server = db.servers.find(s => s.id === req.params.id);
  if (!server) return res.status(404).json({ error: 'Server not found.' });
  db.ftpUsers = (db.ftpUsers || []).filter(u => u.serverId !== server.id);
  writeDb(db);
  try { await recreateSftpContainer(); res.json({ ok: true, enabled: false }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});


async function resourceMonitorTick() {
  const db = readDb();
  for (const server of db.servers || []) {
    try { await enforceResourceLimits(server); }
    catch (e) { console.error('[WARN] Resource monitor failed for', server.name, e.message); }
  }
}
const RESOURCE_MONITOR_INTERVAL_MS = Number(process.env.RESOURCE_MONITOR_INTERVAL_MS || 20000);
setInterval(resourceMonitorTick, RESOURCE_MONITOR_INTERVAL_MS);
setTimeout(resourceMonitorTick, 5000);

app.listen(PORT, () => console.log(`${AGENT_NAME} agent running on port ${PORT}`));
