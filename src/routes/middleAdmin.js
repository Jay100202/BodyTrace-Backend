const express = require('express');
const router = express.Router();
const middleAdmincontroller = require('../controllers/middleAdmincontroller');
const multer = require('multer');

const upload = multer({ dest: 'uploads/' });

// Route to create middle admins from an Excel file
router.post('/create-middle-admins', upload.single('file'), middleAdmincontroller.createMiddleAdminsFromExcel);
router.get('/:email/users', middleAdmincontroller.getUsersByMiddleAdminEmail);
router.post("/getdevicedata", middleAdmincontroller.getDeviceData);

module.exports = router;