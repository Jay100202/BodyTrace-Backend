const User = require('../models/User');
const Admin = require('../models/Admin');

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

// Admin login
exports.adminLogin = async (req, res) => {
    const { email, password } = req.body;

    try {
        const admin = await Admin.findOne({ email });
        if (!admin || admin.password !== password) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        res.status(200).json({ message: 'Admin logged in successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
};