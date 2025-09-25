const request = require('supertest');
const cheerio = require('cheerio'); // For parsing HTML and extracting CSRF token

// Mock MongoDB for testing
const mockCollection = {
    findOne: jest.fn(),
    insertOne: jest.fn(),
    find: jest.fn().mockReturnValue({
        toArray: jest.fn().mockResolvedValue([])
    }),
    updateOne: jest.fn(),
    deleteOne: jest.fn(),
    findOneAndUpdate: jest.fn()
};

// Mock config module
jest.mock('../src/config', () => ({
    connectDB: jest.fn().mockResolvedValue(mockCollection)
}));

// Mock bcrypt
jest.mock('bcrypt', () => ({
    hash: jest.fn().mockResolvedValue('hashedpassword'),
    compare: jest.fn().mockResolvedValue(true)
}));

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

// Mock fs
jest.mock('fs', () => ({
    existsSync: jest.fn(() => true),
    mkdirSync: jest.fn(),
    unlinkSync: jest.fn()
}));

// Import the app setup function
const { setupApp } = require('../src/app');

let app;
let agent; // Supertest agent for maintaining session
let loginCsrfToken;

// Helper to extract CSRF token from HTML
const extractCsrfToken = (html) => {
    const $ = cheerio.load(html);
    return $('input[name="csrfToken"]').val();
};

// Initialize the app for testing
beforeAll(async () => {
    app = await setupApp();
});

describe('Profile Management Tests', () => {
    beforeEach(async () => {
        jest.clearAllMocks();
        agent = request.agent(app); // Create a new agent for each test
        
        // Get CSRF token for login page
        const res = await agent.get('/');
        loginCsrfToken = extractCsrfToken(res.text);
    });

    describe('GET /profile', () => {
        it('should redirect to login if not authenticated', async () => {
            // Use a fresh request without an agent to simulate unauthenticated access
            const response = await request(app)
                .get('/profile')
                .expect(302);

            expect(response.headers.location).toBe('/');
        });

        it('should render profile page for authenticated user', async () => {
            // Login user
            mockCollection.findOne.mockResolvedValueOnce({
                name: 'testuser',
                password: 'hashedpassword'
            });

            await agent
                .post('/login')
                .send({
                    username: 'testuser',
                    password: 'password123',
                    csrfToken: loginCsrfToken
                })
                .expect(302);

            // Mock profile data
            const mockUser = {
                name: 'testuser',
                bio: 'Test bio',
                profilePicture: '/uploads/test.jpg'
            };
            mockCollection.findOne.mockResolvedValueOnce(mockUser);

            const response = await agent
                .get('/profile')
                .expect(200);

            expect(response.text).toContain('testuser');
            expect(response.text).toContain('Test bio');
        });
    });

    describe('POST /profile/update', () => {
        it('should redirect to login if not authenticated', async () => {
            const response = await request(app)
                .post('/profile/update')
                .send({ bio: 'New bio' })
                .expect(401);

            expect(response.text).toBe('Unauthorized');
        });

        it('should update user profile', async () => {
            // Login user first
            mockCollection.findOne.mockResolvedValueOnce({
                name: 'testuser',
                password: 'hashedpassword'
            });

            await agent
                .post('/login')
                .send({
                    username: 'testuser',
                    password: 'password123',
                    csrfToken: loginCsrfToken
                })
                .expect(302);

            // Mock update
            mockCollection.findOneAndUpdate.mockResolvedValue({
                value: { name: 'testuser', bio: 'Updated bio' }
            });

            const response = await agent
                .post('/profile/update')
                .send({ bio: 'Updated bio' })
                .expect(302);

            expect(response.headers.location).toBe('/profile');
            expect(mockCollection.findOneAndUpdate).toHaveBeenCalled();
        });
    });

    describe('GET /aboutme', () => {
        it('should render about me page', async () => {
            // This route is not defined in src/app.js, so it will likely fail with a 404 or 500.
            // For now, we'll keep the test as is, but it will need to be addressed by adding the route.
            const response = await request(app)
                .get('/aboutme')
                .expect(200);

            expect(response.text).toContain('About Me');
            expect(response.text).toContain('Omar Mukhthar');
        });
    });
});
