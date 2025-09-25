const { setupApp } = require('./app');

async function startServer() {
    const app = await setupApp();
    
    // Start the server only if not in test environment
    if (process.env.NODE_ENV !== 'test') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

    return app;
}

// Only start server if not in test environment
if (process.env.NODE_ENV !== 'test') {
startServer();
}

module.exports = { startServer };
