const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    imei: {
        type: [String], // Change imei to an array of strings
        required: true
    },
    resetToken: String, // Token for password reset
    resetTokenExpiry: Date,
    createdAt: {
        type: Date,
        default: Date.now
    },
    type: {
        type: String,
        default: 'user', // Static type field for User
        immutable: true // Prevent changes to this field
    }
});

module.exports = mongoose.model('User', userSchema);