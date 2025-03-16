const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Admin = require('../models/Admin');
const constants = require('../config/constants');

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const authorizeAdmin = async (req, res, next) => {
    try {
        const admin = await Admin.findById(req.user.id);
        if (!admin) return res.status(403).json({ message: constants.NOT_AUTHORIZED });
        next();
    } catch (error) {
        res.status(500).json({ message: constants.SERVER_ERROR });
    }
};

const authorizeUser = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(403).json({ message: constants.NOT_AUTHORIZED });
        next();
    } catch (error) {
        res.status(500).json({ message: constants.SERVER_ERROR });
    }
};

module.exports = {
    authenticateToken,
    authorizeAdmin,
    authorizeUser
};