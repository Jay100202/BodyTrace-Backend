const ERROR_MESSAGES = {
    USER_NOT_FOUND: "User not found.",
    INVALID_CREDENTIALS: "Invalid email or password.",
    DEVICE_NOT_FOUND: "Device not found.",
    USER_ALREADY_EXISTS: "User already exists.",
    EMAIL_SEND_FAILED: "Failed to send email.",
    INVALID_REQUEST: "Invalid request data.",
};

const CONFIG = {
    JWT_SECRET: process.env.JWT_SECRET || "your_jwt_secret",
    EMAIL_SERVICE: process.env.EMAIL_SERVICE || "your_email_service",
    EMAIL_USER: process.env.EMAIL_USER || "your_email_user",
    EMAIL_PASS: process.env.EMAIL_PASS || "your_email_password",
};

module.exports = {
    ERROR_MESSAGES,
    CONFIG,
};