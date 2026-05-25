# Update Notes - Nodes, Status, Backups, Website API Upgrades

This update keeps the existing panel features and adds/fixes:

## Nodes
- Admins can edit node name, URL, public IP, token, and location from Admin -> Nodes.
- Admins can remove a node if no servers are assigned to it.

## Status page
- Added `/status` page.
- Shows node online/offline status, location, public IP, latency, server count, last online time, and last down time.

## Backups
- Added backup slots per user.
- Manual backups now check backup slots before creating a backup.
- Added automatic backup scheduling on the server Backups tab: off/hourly/daily/weekly/monthly.
- Automatic backups still use backup slots.
- Admins can edit backup slots in Admin -> Users.

## Website API / Shop upgrades
Use an API key with these permissions:
- Website: create users
- Website: create servers
- Website: apply upgrades / resources

Provision endpoints:
- `POST /api/v1/provision/order`
- `POST /api/provision/order`
- `POST /api/admin/provision`

Upgrade endpoints:
- `POST /api/v1/provision/upgrade`
- `POST /api/provision/upgrade`
- `POST /api/admin/upgrade`

Example upgrade JSON:

```json
{
  "email": "customer@example.com",
  "serverId": "optional-panel-server-id",
  "portSlots": 2,
  "backupSlots": 5,
  "subdomainSlots": 1,
  "databaseSlots": 1,
  "addMemoryMb": 1024,
  "addStorageMb": 5120,
  "addCpuLimit": 0.5
}
```

Auth headers supported:

```txt
Authorization: Bearer YOUR_API_KEY
```

or:

```txt
x-api-key: YOUR_API_KEY
```
