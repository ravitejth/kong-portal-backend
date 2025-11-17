terraform {
  required_providers {
    konnect = {
      source  = "kong/konnect"
      version = "~> 0.3.0"
    }
  }
}

provider "konnect" {
  personal_access_token = var.kong_pat_token  # Changed from 'pat' to 'personal_access_token'
}

# Import existing service
resource "konnect_gateway_service" "railway_service" {
  control_plane_id = "4dc61f55-0503-4d7c-a8cb-a1d924ae0bfc"
  name             = "railway-service"
  protocol         = "https"
  host             = "kong-portal-backend-production.up.railway.app"
  port             = 443
  path             = "/"
  read_timeout     = 60000
  write_timeout    = 60000
  connect_timeout  = 60000
  retries          = 5
  enabled          = true
}

# Import existing health route
resource "konnect_gateway_route" "health" {
  control_plane_id = "4dc61f55-0503-4d7c-a8cb-a1d924ae0bfc"
  name             = "health"
  paths            = ["/health"]
  protocols        = ["http", "https"]
  strip_path       = false
  preserve_host    = false
  request_buffering  = true
  response_buffering = true
  https_redirect_status_code = 426
  
  service = {
    id = konnect_gateway_service.railway_service.id
  }
}

# Add your other routes
resource "konnect_gateway_route" "users" {
  control_plane_id = "4dc61f55-0503-4d7c-a8cb-a1d924ae0bfc"
  name       = "users-route"
  paths      = ["/api/users"]
  protocols  = ["http", "https"]
  strip_path = false
  preserve_host = false
  
  service = {
    id = konnect_gateway_service.railway_service.id
  }
}