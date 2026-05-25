# Fixes Made

## Website API keys / provisioning

- Added better API-key parsing:
  - `Authorization: Bearer YOUR_API_KEY`
  - `Authorization: ApiKey YOUR_API_KEY`
  - `x-api-key: YOUR_API_KEY`
  - `x-panel-api-key: YOUR_API_KEY`
- Added CORS support for `/api` routes so a website can call the panel API.
- Added a test endpoint: `GET /api/v1/me`.
- Added compatibility provisioning endpoints:
  - `POST /api/v1/provision/order`
  - `POST /api/provision/order`
  - `POST /api/admin/provision`
- Fixed provisioning so the panel server record uses the correct game/server type instead of always saving as `minecraft-paper`.
- Added better JSON errors with `ok: false`.
- Provisioning now supports plan values from Admin → Plans and can grant included extra port slots from the plan.

Example website call:

```bash
curl -X POST https://your-panel-domain/api/v1/provision/order \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "customer@example.com",
    "name": "Customer",
    "serverName": "survival",
    "serverType": "PAPER",
    "memoryMb": 2048,
    "cpuLimit": 1,
    "storageLimitMb": 10240,
    "port": 25565,
    "version": "LATEST",
    "orderId": "stripe_checkout_id"
  }'
```

## Network / extra ports

- Added `portSlots` to users.
- Admins can give users extra port slots from Admin → Users.
- Users must have a free port slot before adding an extra port.
- The panel now checks if a public port is already used before adding it.
- Extra port records now include:
  - public port
  - container port
  - TCP/UDP
  - notes
- Adding/removing an extra port now calls the agent resource endpoint so Docker is recreated with the new port binding while keeping files.
- Agent `/servers/:id/resources` now accepts and saves `networkPorts`.

## Plugins / mods

- Paper, Purpur, Velocity, BungeeCord, and Waterfall show plugins.
- Fabric, Forge, and NeoForge show mods.
- Other game types do not show unsupported plugin/mod installation.
- Add-on search is filtered by the server type.
- Modrinth searches use plugin or mod filters instead of mixing both.
- Manual URL install is locked to the correct type for the server.

## Files changed

- `panel/server.js`
- `panel/views/server.ejs`
- `panel/views/admin.ejs`
- `panel/views/api-keys.ejs`
- `agent/agent.js`
