const mongoose = require('mongoose');

const middleAdminSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    type: { type: String, default: 'middleAdmin' }, // Static type field
    password: { type: String, required: true },
    organization: { type: String, required: true }, // Added organization field
    imeis: { type: [String], required: true }, // Array of IMEI numbers
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

// Check if the model is already compiled
module.exports = mongoose.model('MiddleAdmin', middleAdminSchema);