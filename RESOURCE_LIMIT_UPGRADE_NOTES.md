# Resource Limit Stop + Upgrade System

This update adds a safety system so servers can be stopped when they hit their RAM, CPU, or storage limit.

## What changed

- The agent now checks running servers every 20 seconds.
- If storage reaches the configured server storage limit, the server is stopped.
- If RAM reaches the configured percentage limit, the server is stopped.
- If CPU reaches the configured percentage limit, the server is stopped.
- If Docker kills a container because it ran out of RAM, the panel records that reason too.
- The server page now shows a clear warning explaining why the server stopped.
- The server page now has an Upgrade tab.
- Admins can directly increase RAM, CPU, and storage from the Upgrade tab.
- Normal users see a buy-upgrade button if `UPGRADE_WEBSITE_URL` or `SHOP_UPGRADE_URL` is set in `panel/.env`.
- The existing website upgrade API still works and clears the resource-stop warning when resources are upgraded.

## Optional env settings for the agent

Add these to `agent/.env` if you want custom thresholds:

```env
RESOURCE_MONITOR_INTERVAL_MS=20000
RESOURCE_STOP_MEMORY_PERCENT=99
RESOURCE_STOP_CPU_PERCENT=98
```

## Optional env setting for the panel

Add this to `panel/.env` so users can click a button to buy upgrades from your website:

```env
UPGRADE_WEBSITE_URL=https://your-shop-domain.com/upgrades
```

## Existing upgrade API

Your shop/website can use:

```txt
POST /api/v1/provision/upgrade
POST /api/provision/upgrade
POST /api/admin/upgrade
```

Example body:

```json
{
  "email": "customer@example.com",
  "serverId": "panel-server-id",
  "addMemoryMb": 1024,
  "addStorageMb": 5120,
  "addCpuLimit": 0.5,
  "backupSlots": 2,
  "portSlots": 1,
  "subdomainSlots": 1,
  "databaseSlots": 1
}
```
