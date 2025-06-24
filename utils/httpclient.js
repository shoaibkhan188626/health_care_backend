import axios from 'axios';
import dotenv from 'dotenv';
import logger from '../config/logger.js';

dotenv.config();

const httpClient = axios.create({
  timeout: 5000, // 5s timeout
  headers: {
    'X-Service-Key': process.env.SERVICE_KEY,
  },
});

// Retry logic
const retryRequest = async (config, retries = 3, delay = 1000) => {
  for (let i = 0; i < retries; i++) {
    try {
      return await httpClient(config);
    } catch (error) {
      if (i === retries - 1) {
        logger.error('HTTP request failed after retries', {
          error: error.message,
          url: config.url,
          method: config.method,
        });
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, delay * Math.pow(2, i))); // Exponential backoff
      logger.warn('Retrying HTTP request', { url: config.url, attempt: i + 1 });
    }
  }
};

export const get = async (url, config = {}) => {
  return retryRequest({ ...config, method: 'get', url });
};

export const post = async (url, data, config = {}) => {
  return retryRequest({ ...config, method: 'post', url, data });
};

export default { get, post };