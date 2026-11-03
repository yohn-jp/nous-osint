# Direct Access -> Named Tunnel -> Nous MCP. No Worker or VPC Service.
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
