import crypto from 'crypto';
import logger from '../config/logger.js';

export const generateToken = (length = 32) => {
  try {
    return crypto.randomBytes(length).toString('hex');
  } catch (error) {
    logger.error('Token generation failed', { error: error.message });
    throw error;
  }
};

export const hashToken = (token) => {
  try {
    return crypto.createHash('sha256').update(token).digest('hex');
  } catch (error) {
    logger.error('Token hashing failed', { error: error.message });
    throw error;
  }
};