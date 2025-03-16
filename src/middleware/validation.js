const { body, validationResult } = require('express-validator');

const validateUserCreation = [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('imei').notEmpty().withMessage('IMEI number is required'),
];

const validateDeviceData = [
    body('imei').notEmpty().withMessage('IMEI number is required'),
    body('ts').isNumeric().withMessage('Timestamp must be a number'),
    body('batteryVoltage').isNumeric().withMessage('Battery voltage must be a number'),
    body('signalStrength').isNumeric().withMessage('Signal strength must be a number'),
];

const validateBloodPressureData = [
    body('imei').notEmpty().withMessage('IMEI number is required'),
    body('ts').isNumeric().withMessage('Timestamp must be a number'),
    body('batteryVoltage').isNumeric().withMessage('Battery voltage must be a number'),
    body('signalStrength').isNumeric().withMessage('Signal strength must be a number'),
    body('values.systolic').isNumeric().withMessage('Systolic value must be a number'),
    body('values.diastolic').isNumeric().withMessage('Diastolic value must be a number'),
    body('values.pulse').isNumeric().withMessage('Pulse value must be a number'),
];

const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

module.exports = {
    validateUserCreation,
    validateDeviceData,
    validateBloodPressureData,
    validateRequest,
};