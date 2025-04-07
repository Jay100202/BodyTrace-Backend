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

// Route to edit a user
router.put('/users/:id', userController.editUser);

// Route to fetch device data for a user
router.get('/:id/getuserbyid', userController.getUserbyID);

// Route to fetch device data from BodyTrace API (updated to accept multiple IMEIs)
router.post('/device/data', userController.getDeviceData);

// Route to list users with pagination, sorting, and filtering
router.post('/list/user', userController.listUsers);

// Route to fetch filtered device data (updated to accept multiple IMEIs)
router.post('/device/filtered-data', userController.getFilteredDeviceData);

// Route to download filtered device data as CSV (updated to accept multiple IMEIs)
router.post('/device/downloadCSV', userController.generateDeviceDataCsv);

// Route to request a password reset
router.post('/request-password-reset', userController.requestPasswordReset);

// Route to reset a password
router.post('/reset-password', userController.resetPassword);

// Route to change a password
router.post('/change-password', userController.changePassword);

module.exports = router;