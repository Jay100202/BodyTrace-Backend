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

router.put("/users/:id", userController.editUser)

// Route to fetch device data for a user
router.get('/:id/getuserbyid', userController.getUserbyID);

// Route to fetch device data from BodyTrace API
router.get('/device/:imei', userController.getDeviceData);

router.post("/list/user", userController.listUsers)

router.post("/device/:imei/filtered-data", userController.getFilteredDeviceData)

router.post("/device/:imei/downloadCSV", userController.generateDeviceDataCsv)

router.post("/request-password-reset", userController.requestPasswordReset);

router.post("/reset-password", userController.resetPassword);

router.post("/change-password", userController.changePassword);

module.exports = router;