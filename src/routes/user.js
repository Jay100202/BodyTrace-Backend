const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const { validateUserCreation } = require('../middleware/validation');

// Route to create a new user
router.post('/create', userController.createUser);

// Route to log in a user
router.post('/login', userController.loginUser);

// Route to fetch user data
router.get('/:id', userController.getUserData);

// Route to fetch device data for a user
router.get('/:id/devices', userController.getUserDevices);

// Route to fetch device data from BodyTrace API
router.get('/device/:imei', userController.getDeviceData);

module.exports = router;