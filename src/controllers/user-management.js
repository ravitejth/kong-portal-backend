// src/controllers/user-management.js
const KeycloakService = require('../services/keycloak-service');
const KongService = require('../services/kong-service');

class UserManagementController {
  async createUser(req, res) {
    try {
      const { username, email, firstName, lastName, attributes } = req.body;

      // 1. Create user in Keycloak
      const keycloakUser = await KeycloakService.createUser({
        username,
        email,
        firstName,
        lastName,
        attributes,
      });

      // 2. Create corresponding consumer in Kong
      const kongConsumer = await KongService.createConsumer({
        username,
        custom_id: keycloakUser.id,
        tags: ['managed-by-admin-service'],
      });

      res.status(201).json({
        keycloakUser,
        kongConsumer,
        message: 'User created successfully',
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async assignApiKey(req, res) {
    try {
      const { userId } = req.params;
      const { keyName } = req.body;

      // 1. Get user from Keycloak
      const user = await KeycloakService.getUser(userId);

      // 2. Create API key in Kong for the consumer
      const apiKey = await KongService.createApiKey(user.attributes.kongConsumerId, keyName);

      res.json({ apiKey });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new UserManagementController();
