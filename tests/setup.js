// Test setup file
const path = require('path');

// Mock multer
jest.mock('multer', () => {
    const mockMulter = () => ({
        single: jest.fn(() => (req, res, next) => {
            req.file = null;
            next();
        })
    });
    mockMulter.diskStorage = jest.fn();
    return mockMulter;
});

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-secret';
process.env.ADMIN_SECRET_KEY = '987654';
