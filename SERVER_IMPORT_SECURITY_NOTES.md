# Server templates, Docker import, and security update

## More create-server templates
The admin Create Server tab now uses `SERVER_TEMPLATES` in `panel/server.js`.

Added templates:

- Minecraft Paper
- Minecraft Purpur
- Minecraft Spigot
- Minecraft Bukkit
- Minecraft Pufferfish
- Minecraft Fabric
- Minecraft Quilt
- Minecraft Forge
- Minecraft NeoForge
- Minecraft Mohist
- Minecraft Magma
- Minecraft Vanilla
- Minecraft Custom JAR
- Velocity
- BungeeCord
- Waterfall
- Rust
- Terraria
- Valheim
- Factorio

The UI auto-fills Docker image, game key, port, RAM, storage, and add-on type from the selected template.

## Improved Docker import
The Import Docker tab now has a scan button. It asks the node for Docker containers and shows:

- container name
- image
- status
- mapped ports
- data path / mount
- whether it is already imported

The import code now tries common data locations, not only `/data`:

- `/data`
- `/server`
- `/config`
- `/factorio`
- `/steamcmd/rust`
- `/root/.local/share/Terraria/Worlds`

There is also a managed recreate option. When enabled, the node recreates the existing Docker container with the panel RAM/CPU/port limits while keeping the same data mount.

## Website API improvements
Added these extra API endpoints:

```txt
GET  /api/v1/server-templates
GET  /api/v1/plans
POST /api/v1/provision/user
POST /api/provision/user
POST /api/v1/provision/server
POST /api/provision/server
```

The old compatible endpoints still work:

```txt
POST /api/v1/provision/order
POST /api/provision/order
POST /api/admin/provision
POST /api/v1/provision/upgrade
POST /api/provision/upgrade
POST /api/admin/upgrade
```

## Security improvements
Panel:

- Uses configurable `MAX_BODY_SIZE`
- Uses configurable `TRUST_PROXY`
- API CORS can now be locked to your website with `API_CORS_ORIGIN=https://your-shop-domain.com`
- API keys are still hashed and full keys are only shown once
- Security tab now explains the production settings better

Node/agent:

- Bearer token comparison is now timing-safe
- Optional panel IP allowlist added using `AGENT_ALLOWED_PANEL_IPS`
- Configurable `MAX_AGENT_BODY_SIZE`
- Import scan/import still requires the agent token

Recommended node `.env` additions:

```env
AGENT_ALLOWED_PANEL_IPS=YOUR_PANEL_PUBLIC_IP
MAX_AGENT_BODY_SIZE=20mb
```

Recommended panel `.env` additions:

```env
API_CORS_ORIGIN=https://your-shop-domain.com
TRUST_PROXY=1
MAX_BODY_SIZE=20mb
```
