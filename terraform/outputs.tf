output "service_id" {
  value = konnect_gateway_service.railway_service.id
}

output "route_ids" {
  value = {
    health    = konnect_gateway_route.health.id
    users     = konnect_gateway_route.users.id
  }
}

output "kong_proxy_url" {
  value = "https://kong-1a58e351cfusnx7gs.kongcloud.dev"
}