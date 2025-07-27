
import express from 'express';
import multer from 'multer';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { body, param, validationResult } from 'express-validator';
import { prisma } from '../utils/database';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { asyncHandler } from '../middleware/errorHandler';
import { processDocument } from '../services/documentProcessingService';
import { logger } from '../utils/logger';
import fs from 'fs/promises';

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = process.env.UPLOAD_DIR || 'uploads/documents';
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error as Error, uploadDir);
    }
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const filename = `${uuidv4()}${ext}`;
    cb(null, filename);
  }
});

// File filter for allowed types
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedTypes = ['.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.tif'];
  const allowedMimes = [
    'application/pdf',
    'image/png',
    'image/jpeg',
    'image/jpg',
    'image/tiff',
    'image/tif'
  ];

  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype.toLowerCase();

  if (allowedTypes.includes(ext) && allowedMimes.includes(mime)) {
    cb(null, true);
  } else {
    cb(new Error('Only PDF, PNG, JPEG, and TIFF files are allowed'));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760') // 10MB default
  }
});

// Apply authentication to all routes
router.use(authenticate);

// @desc    Upload document
// @route   POST /api/documents/upload
// @access  Private
router.post('/upload', upload.single('document'), [
  body('taxReturnId').isString().withMessage('Tax return ID is required'),
  body('documentType').optional().isString()
], asyncHandler(async (req: AuthenticatedRequest, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const { taxReturnId, documentType } = req.body;

  try {
    // Verify tax return ownership
    const taxReturn = await prisma.taxReturn.findFirst({
      where: {
        id: taxReturnId,
        userId: req.user!.id
      }
    });

    if (!taxReturn) {
      // Clean up uploaded file
      await fs.unlink(req.file.path);
      return res.status(404).json({ error: 'Tax return not found' });
    }

    // Detect document type if not provided
    const detectedType = documentType || detectDocumentType(req.file.originalname);

    // Create document record
    const document = await prisma.document.create({
      data: {
        taxReturnId,
        fileName: req.file.originalname,
        fileType: req.file.mimetype,
        fileSize: req.file.size,
        filePath: req.file.path,
        documentType: detectedType,
        processingStatus: 'PENDING'
      }
    });

    logger.info(`Document uploaded: ${document.id} for tax return ${taxReturnId}`);

    res.status(201).json({
      id: document.id,
      fileName: document.fileName,
      fileType: document.fileType,
      fileSize: document.fileSize,
      documentType: document.documentType,
      processingStatus: document.processingStatus,
      createdAt: document.createdAt
    });
  } catch (error) {
    // Clean up uploaded file on error
    if (req.file) {
      try {
        await fs.unlink(req.file.path);
      } catch (unlinkError) {
        logger.error('Failed to clean up uploaded file:', unlinkError);
      }
    }
    
    logger.error('Document upload error:', error);
    res.status(500).json({ error: 'Failed to upload document' });
  }
}));

// @desc    Process document with OCR
// @route   POST /api/documents/:id/process
// @access  Private
router.post('/:id/process', [
  param('id').isString().withMessage('Valid document ID required')
], asyncHandler(async (req: AuthenticatedRequest, res) => {
  const { id } = req.params;

  try {
    // Get document and verify ownership
    const document = await prisma.document.findFirst({
      where: {
        id,
        taxReturn: {
          userId: req.user!.id
        }
      },
      include: {
        taxReturn: true
      }
    });

    if (!document) {
      return res.status(404).json({ error: 'Document not found' });
    }

    if (document.processingStatus === 'PROCESSING') {
      return res.status(400).json({ error: 'Document is already being processed' });
    }

    // Update status to processing
    await prisma.document.update({
      where: { id },
      data: { processingStatus: 'PROCESSING' }
    });

    // Set up Server-Sent Events for streaming response
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });

    // Send initial status
    res.write(`data: ${JSON.stringify({ status: 'processing', message: 'Starting document processing...' })}\n\n`);

    try {
      // Process document
      const result = await processDocument(document, (progress) => {
        res.write(`data: ${JSON.stringify({ status: 'progress', ...progress })}\n\n`);
      });

      // Update document with results
      await prisma.document.update({
        where: { id },
        data: {
          processingStatus: 'COMPLETED',
          ocrText: result.ocrText,
          extractedData: result.extractedData,
          updatedAt: new Date()
        }
      });

      // Send completion status
      res.write(`data: ${JSON.stringify({ 
        status: 'completed', 
        extractedData: result.extractedData,
        message: 'Document processing completed successfully'
      })}\n\n`);

      logger.info(`Document processed successfully: ${id}`);
    } catch (processingError) {
      // Update status to failed
      await prisma.document.update({
        where: { id },
        data: { processingStatus: 'FAILED' }
      });

      res.write(`data: ${JSON.stringify({ 
        status: 'error', 
        message: 'Document processing failed',
        error: processingError instanceof Error ? processingError.message : 'Unknown error'
      })}\n\n`);

      logger.error(`Document processing failed: ${id}`, processingError);
    }

    res.end();
  } catch (error) {
    logger.error('Document processing endpoint error:', error);
    res.status(500).json({ error: 'Failed to process document' });
  }
}));

// @desc    Get documents for tax return
// @route   GET /api/tax-returns/:id/documents
// @access  Private
router.get('/tax-returns/:id/documents', [
  param('id').isString().withMessage('Valid tax return ID required')
], asyncHandler(async (req: AuthenticatedRequest, res) => {
  const { id } = req.params;

  try {
    // Verify tax return ownership
    const taxReturn = await prisma.taxReturn.findFirst({
      where: {
        id,
        userId: req.user!.id
      }
    });

    if (!taxReturn) {
      return res.status(404).json({ error: 'Tax return not found' });
    }

    const documents = await prisma.document.findMany({
      where: { taxReturnId: id },
      select: {
        id: true,
        fileName: true,
        fileType: true,
        fileSize: true,
        documentType: true,
        processingStatus: true,
        isVerified: true,
        extractedData: true,
        createdAt: true,
        updatedAt: true
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json(documents);
  } catch (error) {
    logger.error('Get documents error:', error);
    res.status(500).json({ error: 'Failed to fetch documents' });
  }
}));

// @desc    Delete document
// @route   DELETE /api/documents/:id
// @access  Private
router.delete('/:id', [
  param('id').isString().withMessage('Valid document ID required')
], asyncHandler(async (req: AuthenticatedRequest, res) => {
  const { id } = req.params;

  try {
    // Get document and verify ownership
    const document = await prisma.document.findFirst({
      where: {
        id,
        taxReturn: {
          userId: req.user!.id
        }
      }
    });

    if (!document) {
      return res.status(404).json({ error: 'Document not found' });
    }

    // Delete file from filesystem
    try {
      await fs.unlink(document.filePath);
    } catch (fileError) {
      logger.warn(`Failed to delete file: ${document.filePath}`, fileError);
    }

    // Delete document record
    await prisma.document.delete({
      where: { id }
    });

    logger.info(`Document deleted: ${id}`);

    res.json({ message: 'Document deleted successfully' });
  } catch (error) {
    logger.error('Document deletion error:', error);
    res.status(500).json({ error: 'Failed to delete document' });
  }
}));

// Helper function to detect document type from filename
function detectDocumentType(filename: string): string {
  const name = filename.toLowerCase();
  
  if (name.includes('w-2') || name.includes('w2')) return 'W2';
  if (name.includes('1099-int')) return 'FORM_1099_INT';
  if (name.includes('1099-div')) return 'FORM_1099_DIV';
  if (name.includes('1099-misc')) return 'FORM_1099_MISC';
  if (name.includes('1099-nec')) return 'FORM_1099_NEC';
  if (name.includes('1099-r')) return 'FORM_1099_R';
  if (name.includes('1099-g')) return 'FORM_1099_G';
  if (name.includes('1098')) return 'FORM_1098';
  if (name.includes('5498')) return 'FORM_5498';
  if (name.includes('k-1') || name.includes('k1')) return 'SCHEDULE_K1';
  
  return 'UNKNOWN';
}

export default router;
