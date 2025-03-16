const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail', // Use your email service provider
    auth: {
        user: process.env.EMAIL_USER, // Your email address
        pass: process.env.EMAIL_PASS  // Your email password or app password
    }
});

const sendEmail = (to, subject, text) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: to,
        subject: subject,
        text: text
    };

    return transporter.sendMail(mailOptions)
        .then(info => {
            console.log('Email sent: ' + info.response);
            return info;
        })
        .catch(error => {
            console.error('Error sending email: ' + error);
            throw error;
        });
};

module.exports = {
    sendEmail
};