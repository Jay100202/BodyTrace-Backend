const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
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
    type: {
        type: String,
        default: 'admin', // Static type field for Admin
        immutable: true // Prevent changes to this field
    }
}, { timestamps: true });

module.exports = mongoose.model('Admin', adminSchema);