# terraform/main.tf

variable "kong_admin_url" {
  type        = string
  description = "Kong Admin API URL"
}

variable "kong_admin_token" {
  type        = string
  sensitive   = true
  description = "Kong Admin API Token"
}

variable "keycloak_url" {
  type        = string
  description = "Keycloak server URL"
}

variable "keycloak_client_secret" {
  type        = string
  sensitive   = true
  description = "Keycloak client secret"
}

# Docker deployment for your admin service
resource "docker_image" "kong_admin_service" {
  name = "your-org/kong-admin-service:latest"
  keep_locally = false
}

resource "docker_container" "kong_admin_service" {
  name  = "kong-admin-service"
  image = docker_image.kong_admin_service.name
  
  env = [
    "KONG_ADMIN_URL=${var.kong_admin_url}",
    "KONG_ADMIN_TOKEN=${var.kong_admin_token}",
    "KEYCLOAK_URL=${var.keycloak_url}",
    "KEYCLOAK_CLIENT_SECRET=${var.keycloak_client_secret}",
    "NODE_ENV=production"
  ]
  
  ports {
    internal = 3000
    external = 3000
  }
}

# Kong route to expose your admin service
resource "kong_service" "admin_service" {
  name     = "kong-admin-service"
  protocol = "http"
  host     = "kong-admin-service"
  port     = 3000
}

resource "kong_route" "admin_service_route" {
  service_id = kong_service.admin_service.id
  paths      = ["/admin-api/"]
  
  strip_path = false
}

# Plugin to secure your admin service
resource "kong_plugin" "admin_service_auth" {
  service_id = kong_service.admin_service.id
  name       = "key-auth"
  
  config = {
    key_names = ["x-api-key"]
    hide_credentials = true
  }
}