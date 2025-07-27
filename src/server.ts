// src/server.ts - Updated version with proxy trust fix

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import path from 'path';

// Import routes
import authRoutes from './routes/auth';
import taxReturnRoutes from './routes/taxReturns';
import documentRoutes from './routes/documents';
import aiRoutes from './routes/ai';
import debugRoutes from './routes/debug';

// Import middleware
import { errorHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;

// IMPORTANT: Trust proxy settings for Railway deployment
// Railway uses a reverse proxy, so we need to trust it
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1); // Trust first proxy (Railway)
} else {
  // For development, you might want to trust localhost proxies
  app.set('trust proxy', 'loopback');
}

// Security middleware
app.use(helmet());

// Rate limiting with proper proxy configuration for Railway
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Skip rate limiting validation warnings for Railway deployment
  validate: {
    trustProxy: false, // Disable trust proxy validation
    xForwardedForHeader: false, // Disable X-Forwarded-For validation
  },
});
app.use(limiter);

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [
        'https://yourdomain.com',
        'https://tax-backend-clean-production.up.railway.app',
        // Add your frontend domain here when you deploy it
      ] 
    : ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Logging middleware
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));

// Static file serving for uploaded documents
// Use /tmp for Railway deployment
const uploadsPath = process.env.NODE_ENV === 'production' 
  ? '/tmp/uploads' 
  : path.join(__dirname, '../uploads');
app.use('/uploads', express.static(uploadsPath));

// Health check endpoint with more detailed info
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    database: !!process.env.DATABASE_URL,
    jwtSecret: !!process.env.JWT_SECRET,
    trustProxy: app.get('trust proxy'),
    // Show the client IP for debugging
    clientIP: req.ip,
    headers: {
      'x-forwarded-for': req.headers['x-forwarded-for'],
      'x-real-ip': req.headers['x-real-ip']
    }
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/tax-returns', taxReturnRoutes);
app.use('/api/documents', documentRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/debug', debugRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Tax Filing Backend API',
    version: '1.0.0',
    documentation: '/health',
    endpoints: {
      auth: '/api/auth',
      taxReturns: '/api/tax-returns',
      documents: '/api/documents',
      ai: '/api/ai'
    }
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handling middleware (must be last)
app.use(errorHandler);

// Enhanced error handling for deployment
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start server with proper binding for Railway
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`🚀 Tax Filing Backend Server running on port ${PORT}`);
  logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`🔗 Health check: http://localhost:${PORT}/health`);
  logger.info(`💾 Database configured: ${!!process.env.DATABASE_URL}`);
  logger.info(`🔐 JWT Secret configured: ${!!process.env.JWT_SECRET}`);
  logger.info(`🛡️  Trust proxy: ${app.get('trust proxy')}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

export default app;
