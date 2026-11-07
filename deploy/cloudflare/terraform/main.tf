# Access protects both explicit static UI routes and direct Tunnel traffic. No VPC Service.
resource "cloudflare_zero_trust_access_policy" "nous" {
  account_id = var.account_id
  name       = "Allow selected Nous MCP identities"
  decision   = "allow"
  include = [
    for email in sort(tolist(var.allowed_emails)) : {
      email = { email = email }
    }
  ]
}

resource "cloudflare_zero_trust_access_application" "nous" {
  account_id                = var.account_id
  name                      = "Nous OSINT MCP"
  domain                    = "nous.yohn.jp"
  type                      = "mcp"
  allowed_idps              = tolist(var.allowed_idps)
  auto_redirect_to_identity = length(var.allowed_idps) == 1
  policies = [{
    id         = cloudflare_zero_trust_access_policy.nous.id
    precedence = 1
  }]
  oauth_configuration = {
    enabled = true
    grant = {
      access_token_lifetime = "1h"
      session_duration      = "24h"
    }
    dynamic_client_registration = {
      enabled      = true
      allowed_uris = sort(tolist(var.allowed_redirect_uris))
    }
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "nous" {
  account_id = var.account_id
  name       = "nous-osint"
  config_src = "cloudflare"
}

resource "cloudflare_dns_record" "nous" {
  zone_id = var.zone_id
  type    = "CNAME"
  name    = "nous"
  content = format("%s.cfargotunnel.com", cloudflare_zero_trust_tunnel_cloudflared.nous.id)
  proxied = true
  ttl     = 1
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "nous" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.nous.id
  config = {
    ingress = [
      {
        hostname = "nous.yohn.jp"
        service  = var.origin_service
        origin_request = {
          http_host_header = "nous.yohn.jp"
          access = {
            required  = true
            team_name = var.team_name
            aud_tag   = [cloudflare_zero_trust_access_application.nous.aud]
          }
        }
      },
      { service = "http_status:404" }
    ]
  }
}

output "access_audience" {
  value = cloudflare_zero_trust_access_application.nous.aud
}
output "access_issuer" {
  value = format("https://%s.cloudflareaccess.com", var.team_name)
}
output "tunnel_id" {
  value = cloudflare_zero_trust_tunnel_cloudflared.nous.id
}

# UI-only Worker Route patterns; dynamic traffic has no matching Worker Route.
# Exact root path does not match root query URLs; those stay on the retained
# origin fallback until a separate compatible design is approved.
# Cloudflare route wildcards only support trailing *, not infix regex/globs.
locals {
  frontend_static_routes = toset([
    "nous.yohn.jp",
    "nous.yohn.jp/index.html*",
    "nous.yohn.jp/assets/*",
    "nous.yohn.jp/explore*",
    "nous.yohn.jp/live*",
    "nous.yohn.jp/changes*",
    "nous.yohn.jp/sources*",
    "nous.yohn.jp/admin/sources*",
    "nous.yohn.jp/admin/reports*",
    "nous.yohn.jp/items/*",
    "nous.yohn.jp/cves/*",
  ])
}

# CI owns the script and static assets; Terraform owns only these zone routes.
# NEVER attach nous.yohn.jp/*: API/MCP/OAuth/reports must bypass the Worker.
resource "cloudflare_workers_route" "frontend" {
  for_each = var.frontend_route_enabled ? local.frontend_static_routes : toset([])
  zone_id  = var.zone_id
  pattern  = each.value
  script   = "nous-frontend"
}
