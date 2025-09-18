// Example: Export your MongoDB collection or model here
// Replace the following with your actual MongoDB connection and collection/model
const { MongoClient } = require('mongodb');
const uri = process.env.MONGO_URI || 'mongodb://localhost:27017';
const client = new MongoClient(uri);
const dbName = process.env.DB_NAME || 'login';
let collection;

async function connectDB() {
    if (!collection) {
        try {
            await client.connect();
            console.log('Connected to MongoDB');
            const db = client.db(dbName);
            collection = db.collection('users');
        } catch (err) {
            console.error('MongoDB connection error:', err);
            throw err;
        }
    }
<<<<<<< HEAD
    return collection;
}
=======
    
});
>>>>>>> ec867de18a80236e2b318efa1eba9ec97ba5b1d7

module.exports = { connectDB };
