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
let signupCsrfToken;

// Helper to extract CSRF token from HTML
const extractCsrfToken = (html) => {
    const $ = cheerio.load(html);
    return $('input[name="csrfToken"]').val();
};

// Initialize the app for testing
beforeAll(async () => {
    app = await setupApp();
});

describe('Authentication Tests', () => {
    beforeEach(async () => {
        jest.clearAllMocks();
        agent = request.agent(app); // Create a new agent for each test
        
        // Get CSRF token for login page
        const loginRes = await agent.get('/');
        loginCsrfToken = extractCsrfToken(loginRes.text);

        // Get CSRF token for signup page
        const signupRes = await agent.get('/signup');
        signupCsrfToken = extractCsrfToken(signupRes.text);
    });

    describe('GET /', () => {
        it('should render login page', async () => {
            const response = await agent
                .get('/')
                .expect(200);
            
            expect(response.text).toContain('Login');
            expect(loginCsrfToken).toBeDefined();
        });
    });

    describe('POST /login', () => {
        it('should login with valid credentials', async () => {
            mockCollection.findOne.mockResolvedValue({
                name: 'testuser',
                password: 'hashedpassword'
            });

            const response = await agent
                .post('/login')
                .send({
                    username: 'testuser',
                    password: 'password123',
                    csrfToken: loginCsrfToken
                })
                .expect(302);

            expect(response.headers.location).toBe('/home');
        });

        it('should reject invalid credentials', async () => {
            mockCollection.findOne.mockResolvedValue(null);

            const response = await agent
                .post('/login')
                .send({
                    username: 'nonexistent',
                    password: 'wrongpassword',
                    csrfToken: loginCsrfToken
                })
                .expect(401);

            expect(response.body.error).toBe('Invalid credentials'); // Expect JSON error
        });

        it('should reject wrong password', async () => {
            const bcrypt = require('bcrypt');
            bcrypt.compare.mockResolvedValueOnce(false);
            
            mockCollection.findOne.mockResolvedValue({
                name: 'testuser',
                password: 'hashedpassword'
            });

            const response = await agent
                .post('/login')
                .send({
                    username: 'testuser',
                    password: 'wrongpassword',
                    csrfToken: loginCsrfToken
                })
                .expect(401);

            expect(response.body.error).toBe('Invalid credentials'); // Expect JSON error
        });
    });

    describe('POST /signup', () => {
        it('should create new user', async () => {
            mockCollection.findOne.mockResolvedValue(null);
            mockCollection.insertOne.mockResolvedValue({ insertedId: 'newid' });

            const response = await agent
                .post('/signup')
                .field('username', 'newuser')
                .field('password', 'password123')
                .field('bio', 'Test bio')
                .field('csrfToken', signupCsrfToken) // Use signupCsrfToken
                .expect(302);

            expect(response.headers.location).toBe('/home');
            expect(mockCollection.insertOne).toHaveBeenCalledWith(
                expect.objectContaining({
                    name: 'newuser',
                    bio: 'Test bio'
                })
            );
        });

        it('should reject existing user', async () => {
            mockCollection.findOne.mockResolvedValue({
                name: 'existinguser',
                password: 'hashedpassword'
            });

            const response = await agent
                .post('/signup')
                .field('username', 'existinguser')
                .field('password', 'password123')
                .field('csrfToken', signupCsrfToken) // Use signupCsrfToken
                .expect(400);

            expect(response.body.error).toBe('Username already exists'); // Expect JSON error
        });
    });

    describe('GET /home', () => {
        it('should redirect to login if not authenticated', async () => {
            // Use a fresh request without an agent to simulate unauthenticated access
            const response = await request(app)
                .get('/home')
                .expect(302);

            expect(response.headers.location).toBe('/');
        });

        it('should render home page for authenticated user', async () => {
            mockCollection.findOne.mockResolvedValue({
                name: 'authenticateduser',
                password: 'hashedpassword',
                profilePicture: '/default-profile.png'
            });

            // First, log in to get an authenticated session
            await agent
                .post('/login')
                .send({
                    username: 'authenticateduser',
                    password: 'password123',
                    csrfToken: loginCsrfToken
                })
                .expect(302);

            const response = await agent
                .get('/home')
                .expect(200);

            expect(response.text).toContain('authenticateduser');
            expect(response.text).toContain('Home');
        });
    });

    describe('GET /signout', () => {
        it('should destroy session and redirect to login', async () => {
            // First, log in to get an authenticated session
            mockCollection.findOne.mockResolvedValue({
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

            const response = await agent
                .get('/signout')
                .expect(302);

            expect(response.headers.location).toBe('/');
        });
    });
});
