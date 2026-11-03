variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[a-f0-9]{32}$", var.account_id))
    error_message = "Provide a real Cloudflare account ID."
  }
}
variable "zone_id" {
  type = string
  validation {
    condition     = can(regex("^[a-f0-9]{32}$", var.zone_id))
    error_message = "Provide a real Cloudflare DNS zone ID."
  }
}
variable "team_name" {
  type = string
  description = "Access team prefix before .cloudflareaccess.com"
  validation {
    condition = can(regex("^[a-z0-9-]+$", var.team_name))
    error_message = "Provide an Access team prefix."
  }
}
variable "allowed_emails" {
  type = set(string)
  description = "Explicit per-user Access allowlist; empty is forbidden."
  validation {
    condition = length(var.allowed_emails) > 0 && alltrue([
      for email in var.allowed_emails :
      can(regex("^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$", email))
    ])
    error_message = "Set at least one valid explicit user email."
  }
}
variable "allowed_idps" {
  type = set(string)
  description = "Existing Cloudflare Access IdP IDs."
  validation {
    condition = length(var.allowed_idps) > 0
    error_message = "Explicit IdP allowlist must not be empty."
  }
}
variable "allowed_redirect_uris" {
  type = set(string)
  description = "Exact observed HTTPS OAuth callback URI(s), e.g. the actual ChatGPT client callback."
  validation {
    condition = length(var.allowed_redirect_uris) > 0 && alltrue([
      for uri in var.allowed_redirect_uris :
      startswith(uri, "https://") && !strcontains(uri, "*") &&
      !strcontains(uri, "localhost") && !strcontains(uri, "127.0.0.1")
    ])
    error_message = "Only exact non-loopback HTTPS OAuth redirect URIs are allowed."
  }
}
variable "origin_service" {
  type    = string
  default = "http://nous-mcp:8001"
  validation {
    condition     = var.origin_service == "http://nous-mcp:8001"
    error_message = "Tunnel ingress must target the dedicated MCP container."
  }
}
