#!/bin/bash

echo "Initializing Terraform..."
terraform init

echo "Importing service..."
terraform import konnect_gateway_service.railway_service '{"control_plane_id":"4dc61f55-0503-4d7c-a8cb-a1d924ae0bfc","id":"4b0dbfa3-dc2c-4db7-9d0d-d81b0f5a52d6"}'

echo "Importing health route..."
terraform import konnect_gateway_route.health '{"control_plane_id":"4dc61f55-0503-4d7c-a8cb-a1d924ae0bfc","id":"f5e1be9d-4fe0-4433-a4e3-d2b5aa310257"}'

echo "Planning configuration..."
terraform plan

echo "Applying configuration..."
terraform apply -auto-approve

echo "Testing endpoints..."
curl https://kong-1a58e351cfusnx7gs.kongcloud.dev/health