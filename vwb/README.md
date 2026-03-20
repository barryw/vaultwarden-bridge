# vwb — Vaultwarden Bridge CLI

A single-purpose CLI that fetches secrets from a [Vaultwarden Bridge](https://github.com/barryw/vaultwarden-bridge) instance. Designed for CI pipelines.

## Install

Download the latest binary for your platform from [GitHub Releases](https://github.com/barryw/vaultwarden-bridge/releases):

```bash
# Linux amd64
curl -fsSL https://github.com/barryw/vaultwarden-bridge/releases/latest/download/vwb-linux-amd64 -o /usr/local/bin/vwb
chmod +x /usr/local/bin/vwb

# Linux arm64
curl -fsSL https://github.com/barryw/vaultwarden-bridge/releases/latest/download/vwb-linux-arm64 -o /usr/local/bin/vwb
chmod +x /usr/local/bin/vwb
```

Or build from source:

```bash
cargo install --git https://github.com/barryw/vaultwarden-bridge --bin vwb
```

## Configuration

Two environment variables, both required:

| Variable | Description |
|----------|-------------|
| `VWB_ADDR` | Bridge server URL (e.g. `https://vault-bridge.lan`) |
| `VWB_TOKEN` | Machine API key (created in the Bridge web UI) |

Put both in your CI system's secrets store.

## Usage

```bash
vwb get <key>
```

Prints the secret value to stdout. Errors go to stderr. Exit code 0 on success, 1 on failure.

### CI Examples

**Woodpecker CI:**
```yaml
steps:
  - name: deploy
    image: alpine
    environment:
      VWB_ADDR:
        from_secret: vwb_addr
      VWB_TOKEN:
        from_secret: vwb_token
    commands:
      - curl -fsSL https://github.com/barryw/vaultwarden-bridge/releases/latest/download/vwb-linux-amd64 -o /usr/local/bin/vwb && chmod +x /usr/local/bin/vwb
      - export DB_PASSWORD=$(vwb get prod/db/password)
      - export API_TOKEN=$(vwb get prod/api/token)
      - ./deploy.sh
```

**GitHub Actions:**
```yaml
- name: Fetch secrets
  env:
    VWB_ADDR: ${{ secrets.VWB_ADDR }}
    VWB_TOKEN: ${{ secrets.VWB_TOKEN }}
  run: |
    curl -fsSL https://github.com/barryw/vaultwarden-bridge/releases/latest/download/vwb-linux-amd64 -o /usr/local/bin/vwb && chmod +x /usr/local/bin/vwb
    echo "DB_PASSWORD=$(vwb get prod/db/password)" >> $GITHUB_ENV
```

**Terraform / OpenTofu:**
```bash
export TF_VAR_db_password=$(vwb get prod/db/password)
terraform apply
```

**Inline:**
```bash
docker login -u admin -p $(vwb get registry/password) ghcr.io
```

## Error Handling

| Scenario | stderr | Exit code |
|----------|--------|-----------|
| Missing `VWB_ADDR` | `error: VWB_ADDR environment variable is not set` | 1 |
| Missing `VWB_TOKEN` | `error: VWB_TOKEN environment variable is not set` | 1 |
| Bad token | `error: unauthorized` | 1 |
| No access | `error: access denied` | 1 |
| Key not found | `error: not found: <key>` | 1 |
| Network error | `error: <details>` | 1 |
| Success | *(nothing on stderr)* | 0 |

## Audit Trail

Every `vwb get` call is logged in the Bridge's audit log with:
- Which machine key was used
- What secret was requested
- Source IP
- Client version (`vwb/<version>` via User-Agent)
