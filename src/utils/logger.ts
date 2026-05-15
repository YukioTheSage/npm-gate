import pino from 'pino';

export const logger = pino({
  level: process.env.NPM_GATE_LOG_LEVEL ?? 'silent',
  redact: {
    paths: ['req.headers.authorization', '*.token', '*.authToken', '*.password'],
    censor: '[redacted]'
  }
});
