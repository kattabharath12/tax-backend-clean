
import express from 'express';
import { body, validationResult } from 'express-validator';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { generateTaxStrategies } from '../services/aiOptimizationService';
import { logger } from '../utils/logger';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticate);

// @desc    Get AI-powered tax optimization strategies
// @route   POST /api/ai/tax-strategies
// @access  Private
router.post('/tax-strategies', [
  body('taxReturnData').isObject().withMessage('Tax return data is required')
], asyncHandler(async (req: AuthenticatedRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { taxReturnData } = req.body;

  try {
    logger.info(`Generating tax strategies for user ${req.user!.id}`);

    const strategies = await generateTaxStrategies(taxReturnData);

    res.json({
      strategies,
      generatedAt: new Date().toISOString(),
      disclaimer: 'These are AI-generated suggestions and should not be considered professional tax advice. Please consult with a qualified tax professional.'
    });
  } catch (error) {
    logger.error('Tax strategies generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate tax strategies',
      message: 'Our AI service is temporarily unavailable. Please try again later.'
    });
  }
}));

// @desc    Get tax optimization recommendations
// @route   POST /api/ai/optimize
// @access  Private
router.post('/optimize', [
  body('scenario').isObject().withMessage('Tax scenario data is required')
], asyncHandler(async (req: AuthenticatedRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { scenario } = req.body;

  try {
    // Mock optimization response for now
    const optimizations = [
      {
        category: 'Deductions',
        recommendation: 'Consider maximizing your retirement contributions',
        potentialSavings: 1200,
        confidence: 0.85,
        explanation: 'Based on your income level, increasing 401(k) contributions could reduce your taxable income significantly.'
      },
      {
        category: 'Credits',
        recommendation: 'Explore education tax credits',
        potentialSavings: 800,
        confidence: 0.70,
        explanation: 'If you or your dependents are pursuing higher education, you may qualify for education credits.'
      },
      {
        category: 'Timing',
        recommendation: 'Consider tax-loss harvesting',
        potentialSavings: 500,
        confidence: 0.60,
        explanation: 'If you have investment losses, they can be used to offset capital gains.'
      }
    ];

    logger.info(`Tax optimization generated for user ${req.user!.id}`);

    res.json({
      optimizations,
      totalPotentialSavings: optimizations.reduce((sum, opt) => sum + opt.potentialSavings, 0),
      generatedAt: new Date().toISOString(),
      disclaimer: 'These are AI-generated suggestions and should not be considered professional tax advice.'
    });
  } catch (error) {
    logger.error('Tax optimization error:', error);
    res.status(500).json({ error: 'Failed to generate optimization recommendations' });
  }
}));

export default router;
