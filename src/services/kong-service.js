// src/services/kong-service.js
const axios = require('axios');

class KongService {
  constructor() {
    this.kongAdminUrl = process.env.KONG_ADMIN_URL;
    this.kongAdminToken = process.env.KONG_ADMIN_TOKEN;

    this.client = axios.create({
      baseURL: this.kongAdminUrl,
      headers: {
        Authorization: `Bearer ${this.kongAdminToken}`,
        'Content-Type': 'application/json',
      },
    });
  }

  async createConsumer(consumerData) {
    const response = await this.client.post('/consumers', consumerData);
    return response.data;
  }

  async createService(serviceData) {
    const response = await this.client.post('/services', serviceData);
    return response.data;
  }

  async createRoute(serviceId, routeData) {
    const response = await this.client.post(`/services/${serviceId}/routes`, routeData);
    return response.data;
  }

  async createPlugin(pluginData) {
    const response = await this.client.post('/plugins', pluginData);
    return response.data;
  }

  async createApiKey(consumerId, keyName = 'default') {
    const response = await this.client.post(`/consumers/${consumerId}/key-auth`, {
      key: this.generateApiKey(),
      tags: [keyName, 'generated-by-admin-service'],
    });
    return response.data;
  }

  generateApiKey() {
    return `kong_${require('crypto').randomBytes(32).toString('hex')}`;
  }
}

module.exports = new KongService();
