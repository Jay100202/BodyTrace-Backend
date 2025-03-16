const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');

// Define your routes here
router.post('/create-user', adminController.createUser);
router.get('/users', adminController.getAllUsers);
router.get('/user/:imei', adminController.getUserByImei);
router.post('/login', adminController.adminLogin);

module.exports = router;