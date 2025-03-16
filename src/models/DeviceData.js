const mongoose = require('mongoose');

const deviceDataSchema = new mongoose.Schema({
    imei: {
        type: String,
        required: true
    },
    dateTime: {
        type: Date,
        required: true
    },
    batteryVoltage: {
        type: Number,
        required: true
    },
    signalStrength: {
        type: Number,
        required: true
    },
    rssi: {
        type: Number,
        required: true
    },
    deviceId: {
        type: String,
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    }
}, { timestamps: true });

module.exports = mongoose.model('DeviceData', deviceDataSchema);