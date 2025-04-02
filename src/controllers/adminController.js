const User = require('../models/User');
const Admin = require('../models/Admin');
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
            // Use bcrypt to compare the hashed password with the plain text password
            const isPasswordMatch = await bcrypt.compare(password, user.password);
            if (!isPasswordMatch) {
                console.log("Password mismatch for user:", email);
                return res.status(401).json({ message: 'Invalid credentials' });
            }
            if (!user.imei) {
                console.log("IMEI number is missing for user:", email);
                return res.status(400).json({ message: 'IMEI number is missing for user' });
            }
            console.log("User login successful:", email);
            return res.status(200).json({
                message: 'User logged in successfully',
                user: {
                    email: user.email,
                    imei: user.imei,
                    name: user.name,
                    type: user.type,
                },
            });
        }

        // If not found in User, check in Admin collection
        console.log("User not found in User collection, checking Admin collection for email:", email);
        const admin = await Admin.findOne({ email });

        console.log("Admin found in Admin collection:", admin); // Log the admin object if found
        if (admin) {
            console.log("Admin exists, checking password...");
            // Use normal string comparison for admin password
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

        // If neither User nor Admin is found
        console.log("No User or Admin found for email:", email);
        return res.status(404).json({ message: 'User or Admin not found' });
    } catch (error) {
        console.error("Error occurred during login:", error); // Log the error
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
};