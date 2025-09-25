const request = require('supertest');

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

// Initialize the app for testing
beforeAll(async () => {
    app = await setupApp();
});

describe('Admin CRUD Tests', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('Admin Authentication', () => {
        it('should render admin login page', async () => {
            const response = await request(app)
                .get('/admin')
                .expect(200);
            
            expect(response.text).toContain('Admin Login');
        });

        it('should login admin with correct key', async () => {
            const response = await request(app)
                .post('/admin')
                .send({ adminKey: '987654' })
                .expect(302);

            expect(response.headers.location).toBe('/admin/dashboard');
        });

        it('should reject admin login with wrong key', async () => {
            const response = await request(app)
                .post('/admin')
                .send({ adminKey: 'wrongkey' })
                .expect(403);

            expect(response.text).toBe('Invalid Admin Key');
        });
    });

    describe('Admin Dashboard', () => {
        it('should redirect to admin login if not authenticated', async () => {
            const response = await request(app)
                .get('/admin/dashboard')
                .expect(302);

            expect(response.headers.location).toBe('/admin');
        });
    });

    describe('Admin User Management', () => {
        const adminAgent = request.agent(app);

        beforeEach(async () => {
            // Login as admin
            await adminAgent
                .post('/admin')
                .send({ adminKey: '987654' });
        });

        it('should create new user', async () => {
            mockCollection.findOne.mockResolvedValue(null);
            mockCollection.insertOne.mockResolvedValue({ insertedId: 'newid' });

            const response = await adminAgent
                .post('/admin/create')
                .send({
                    username: 'newuser',
                    password: 'password123'
                })
                .expect(302);

            expect(response.headers.location).toBe('/admin/dashboard');
            expect(mockCollection.insertOne).toHaveBeenCalledWith(
                expect.objectContaining({
                    name: 'newuser',
                    bio: '',
                    profilePicture: ''
                })
            );
        });

        it('should reject creating existing user', async () => {
            mockCollection.findOne.mockResolvedValue({
                name: 'existinguser',
                password: 'hashedpassword'
            });

            const response = await adminAgent
                .post('/admin/create')
                .send({
                    username: 'existinguser',
                    password: 'password123'
                })
                .expect(400);

            expect(response.text).toBe('User already exists');
        });

        it('should update user', async () => {
            mockCollection.updateOne.mockResolvedValue({ modifiedCount: 1 });

            const response = await adminAgent
                .post('/admin/edit')
                .send({
                    id: 'userid123',
                    username: 'updateduser',
                    password: 'newpassword'
                })
                .expect(302);

            expect(response.headers.location).toBe('/admin/dashboard');
            expect(mockCollection.updateOne).toHaveBeenCalled();
        });

        it('should delete user', async () => {
            mockCollection.deleteOne.mockResolvedValue({ deletedCount: 1 });

            const response = await adminAgent
                .post('/admin/delete')
                .send({ id: 'userid123' })
                .expect(302);

            expect(response.headers.location).toBe('/admin/dashboard');
            expect(mockCollection.deleteOne).toHaveBeenCalled();
        });

        it('should search users', async () => {
            const mockUsers = [
                { _id: '1', name: 'user1', bio: 'bio1', profilePicture: '' },
                { _id: '2', name: 'user2', bio: 'bio2', profilePicture: '' }
            ];
            
            mockCollection.find.mockReturnValue({
                toArray: jest.fn().mockResolvedValue(mockUsers)
            });

            const response = await adminAgent
                .get('/admin/search?username=user1')
                .expect(200);

            expect(response.text).toContain('user1');
        });
    });

    describe('Admin Logout', () => {
        it('should logout admin and redirect to admin login', async () => {
            const adminAgent = request.agent(app);
            
            // Login as admin first
            await adminAgent
                .post('/admin')
                .send({ adminKey: '987654' });

            // Then logout
            const response = await adminAgent
                .get('/admin/logout')
                .expect(302);

            expect(response.headers.location).toBe('/admin');
        });
    });
});
