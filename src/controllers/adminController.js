const User = require('../models/User');
const Admin = require('../models/Admin');
const MiddleAdmin = require('../models/middleAdmin'); // Use consistent casing
const bcrypt = require('bcrypt'); // Import bcrypt for password comparison

// Create a new admin user
exports.createUser = async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const newAdmin = new Admin({ name, email, password });
        await newAdmin.save();

        res.status(201).json({ message: 'Admin created successfully', admin: newAdmin });
    } catch (error) {
        res.status(500).json({ message: 'Error creating admin', error: error.message });
    }
};

// Get all users
exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
};

// Get user by IMEI
exports.getUserByImei = async (req, res) => {
    const { imei } = req.params;

    try {
        const user = await User.findOne({ imei });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user', error: error.message });
    }
};


exports.adminLogin = async (req, res) => {
    const { email, password } = req.body;

    console.log("Login request received with email:", email); // Log the incoming request

    try {
        // Check if the user exists in the User collection
        console.log("Checking User collection for email:", email);
        const user = await User.findOne({ email });

        console.log("User found in User collection:", user); // Log the user object if found
        if (user) {
            console.log("User exists, checking password and IMEI...");
            if (user.password !== password) {
                console.log("Password mismatch for user:", email);
                return res.status(401).json({ message: 'Invalid credentials' });
            }
            if (!user.imei) {
                console.log("IMEI number is missing for user:", email);
                return res.status(400).json({ message: 'IMEI number is missing for user' });
            }

            // Update the last login time
            user.lastLogin = new Date();
            await user.save();

            console.log("User login successful:", email);
            return res.status(200).json({
                message: 'User logged in successfully',
                user: {
                    email: user.email,
                    imei: user.imei,
                    name: user.name,
                    type: user.type,
                    lastLogin: user.lastLogin, // Include last login in the response
                },
            });
        }

        // If not found in User, check in Admin collection
        console.log("User not found in User collection, checking Admin collection for email:", email);
        const admin = await Admin.findOne({ email });

        console.log("Admin found in Admin collection:", admin); // Log the admin object if found
        if (admin) {
            console.log("Admin exists, checking password...");
            if (admin.password !== password) {
                console.log("Password mismatch for admin:", email);
                return res.status(401).json({ message: 'Invalid credentials' });
            }
            console.log("Admin login successful:", email);
            return res.status(200).json({
                message: 'Admin logged in successfully',
                user: {
                    email: admin.email,
                    name: admin.name,
                    type: admin.type,
                },
            });
        }

        // If not found in Admin, check in MiddleAdmin collection
        console.log("User not found in Admin collection, checking MiddleAdmin collection for email:", email);
        const middleAdmin = await MiddleAdmin.findOne({ email });

        console.log("MiddleAdmin found in MiddleAdmin collection:", middleAdmin); // Log the middle admin object if found
        if (middleAdmin) {
            console.log("MiddleAdmin exists, checking password...");
            if (middleAdmin.password !== password) {
                console.log("Password mismatch for middle admin:", email);
                return res.status(401).json({ message: 'Invalid credentials' });
            }
            console.log("MiddleAdmin login successful:", email);
            return res.status(200).json({
                message: 'Middle admin logged in successfully',
                user: {
                    email: middleAdmin.email,
                    name: middleAdmin.name,
                    type: middleAdmin.type,
                },
            });
        }

        // If neither User, Admin, nor MiddleAdmin is found
        console.log("No User, Admin, or MiddleAdmin found for email:", email);
        return res.status(404).json({ message: 'User, Admin, or MiddleAdmin not found' });
    } catch (error) {
        console.error("Error occurred during login:", error); // Log the error
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
};