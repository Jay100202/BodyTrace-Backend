require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const adminRoutes = require('./src/routes/admin');
const userRoutes = require('./src/routes/user');
const connectDB = require('./src/config/db'); // Import the connectDB function

const app = express();

// CORS Configuration
const corsOptions = {
    origin: 'https://bodytrace-frontend.onrender.com', // Replace with your frontend's URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed HTTP methods
    credentials: true, // Allow cookies and credentials
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Handle preflight requests

// Middleware
app.use(bodyParser.json());

// Routes
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);

// Database connection
connectDB(); // Call the connectDB function to connect to the database

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});