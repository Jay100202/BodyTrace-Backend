require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const adminRoutes = require('./src/routes/admin');
const userRoutes = require('./src/routes/user');
const middleAdminRoutes = require('./src/routes/middleAdmin'); // Import the middle admin routes
const connectDB = require('./src/config/db'); // Import the connectDB function

const app = express();

// CORS Configuration - More permissive configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = ['https://bodytrace-frontend.onrender.com', 'http://localhost:3000'];
        // Allow requests with no origin (like mobile apps, curl requests, etc.)
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(null, true); // Allow all origins in development
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    maxAge: 86400 // Cache preflight request for 1 day
};

// Apply CORS middleware first, before any routes
app.use(cors(corsOptions));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Add a diagnostic route to test CORS
app.get('/api/cors-test', (req, res) => {
    res.json({ message: 'CORS is working properly!' });
});

// Routes
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);
app.use('/api/middle-admin', middleAdminRoutes); // Use the middle admin routes

// Error handler for CORS issues
app.use((err, req, res, next) => {
    if (err.name === 'CORSError') {
        console.error('CORS Error:', err);
        return res.status(403).json({ error: 'CORS error', details: err.message });
    }
    next(err);
});

// Database connection
connectDB(); // Call the connectDB function to connect to the database

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`CORS configured for: ${corsOptions.origin}`);
});