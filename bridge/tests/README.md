# Integration Testing

## Prerequisites

- Docker and Docker Compose
- A running Vaultwarden instance
- A Vaultwarden account with at least one login item
- Go 1.23+ (for building the Terraform provider)
- Terraform 1.0+

## 1. Start the Database

```bash
docker compose up db -d
```

## 2. Configure Environment

Copy `.env.example` to `.env` and fill in your Vaultwarden details:

```bash
cp .env.example .env
# Edit .env with your Vaultwarden URL, email, and password
```

## 3. Start the Bridge

```bash
cargo run
```

The bridge will:
1. Connect to PostgreSQL and run migrations
2. Log into Vaultwarden and start `bw serve`
3. Begin listening on `http://localhost:8080`

## 4. Configure via Web UI

1. Open `http://localhost:8080/ui/login`
2. Log in with the admin credentials from your `.env`
3. Go to **Machine Keys** → create a new key
4. **Copy the API key** (shown only once)
5. Go to the key's **Policies** → add a policy:
   - Type: `glob`, Value: `*` (allows access to everything, for testing)

## 5. Test the API

```bash
curl -s -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/api/v1/secret/YOUR_ITEM_NAME | jq
```

Expected response:
```json
{
  "key": "YOUR_ITEM_NAME",
  "value": "the-secret-value",
  "updated_at": "2026-03-18T12:00:00Z"
}
```

## 6. Test with Terraform

Build the provider:

```bash
cd terraform-provider-vaultwarden
go build -o terraform-provider-vaultwarden
```

Create a dev override in `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "registry.terraform.io/vaultwarden-bridge/vaultwarden" = "/path/to/terraform-provider-vaultwarden"
  }
  direct {}
}
```

Create a test configuration:

```hcl
terraform {
  required_providers {
    vaultwarden = {
      source = "registry.terraform.io/vaultwarden-bridge/vaultwarden"
    }
  }
}

provider "vaultwarden" {
  address = "http://localhost:8080"
  api_key = "YOUR_API_KEY"
}

data "vaultwarden_secret" "test" {
  key = "YOUR_ITEM_NAME"
}

output "secret_value" {
  value     = data.vaultwarden_secret.test.value
  sensitive = true
}

output "secret_updated_at" {
  value = data.vaultwarden_secret.test.updated_at
}
```

Run:

```bash
terraform plan
terraform apply
```

## 7. Verify Audit Log

Go back to the Web UI → **Audit Log** and verify you see entries for the API calls and Terraform reads.

## 8. Test Access Denial

1. Remove the glob `*` policy from the machine key
2. Add a specific policy (e.g., type: `item`, value: `some-other-item`)
3. Re-run the curl command for the original item
4. Verify you get a 403 response
5. Check the audit log shows `access_denied`

## Full Docker Deployment

To test the complete Docker deployment:

```bash
docker compose up --build
```

This starts both the bridge and PostgreSQL. Configure via environment variables in `.env`.
