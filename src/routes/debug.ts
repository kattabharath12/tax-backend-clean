
import express from 'express';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { prisma } from '../utils/database';
import { calculateTaxes } from '../services/taxCalculationService';
import { logger } from '../utils/logger';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticate);

// @desc    Get debug tax data
// @route   GET /api/debug/tax-data
// @access  Private (Development only)
router.get('/tax-data', asyncHandler(async (req: AuthenticatedRequest, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Debug endpoints not available in production' });
  }

  try {
    const taxReturns = await prisma.taxReturn.findMany({
      where: { userId: req.user!.id },
      include: {
        incomeEntries: true,
        deductionEntries: true,
        dependents: true,
        documents: true
      }
    });

    const debugData = {
      user: req.user,
      taxReturns: taxReturns.map(tr => ({
        ...tr,
        calculatedTaxes: calculateTaxes(tr)
      })),
      systemInfo: {
        nodeEnv: process.env.NODE_ENV,
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      }
    };

    res.json(debugData);
  } catch (error) {
    logger.error('Debug tax data error:', error);
    res.status(500).json({ error: 'Failed to fetch debug data' });
  }
}));

// @desc    Test tax calculations
// @route   POST /api/debug/test-calculations
// @access  Private (Development only)
router.post('/test-calculations', asyncHandler(async (req: AuthenticatedRequest, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(403).json({ error: 'Debug endpoints not available in production' });
  }

  const { taxReturnData } = req.body;

  try {
    const calculations = await calculateTaxes(taxReturnData);
    
    res.json({
      input: taxReturnData,
      calculations,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Test calculations error:', error);
    res.status(500).json({ error: 'Failed to test calculations' });
  }
}));

export default router;
