const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // Import axios for making HTTP requests
const crypto = require('crypto'); // For generating random tokens
const nodemailer = require('nodemailer'); // For sending emails
const { Parser } = require('json2csv'); // Import json2csv for CSV generation
// Function to create a new user

exports.createUser = async (req, res) => {
    const { name, email, password, imei } = req.body;

    console.log('Request Body:', req.body);

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ name, email, password: hashedPassword, imei: Array.isArray(imei) ? imei : [imei] });
        await newUser.save();

        // Generate a JWT token
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Send welcome email with credentials
        try {
            // Create email transporter
            const transporter = nodemailer.createTransport({
                service: 'Gmail', // Use your email service
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            // Email content
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Welcome to BodyTrace - Your Account Information',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2>Welcome to BodyTrace!</h2>
                        <p>Hello ${name},</p>
                        <p>Your account has been successfully created. Here are your login credentials:</p>
                        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
                            <p><strong>Email:</strong> ${email}</p>
                            <p><strong>Password:</strong> ${password}</p>
                            <p><strong>IMEI(s):</strong> ${newUser.imei.join(', ')}</p>
                        </div>
                        <p>Please keep this information secure and consider changing your password after your first login.</p>
                        <p>You can log in by visiting our website or mobile app.</p>
                        <p>Thank you for choosing BodyTrace!</p>
                        <p>Best regards,<br>The BodyTrace Team</p>
                    </div>
                `
            };

            // Send email
            await transporter.sendMail(mailOptions);
            console.log('Credentials email sent to user');
            
        } catch (emailError) {
            // If email sending fails, log the error but don't fail the user creation
            console.error('Failed to send credentials email:', emailError);
        }

        res.status(201).json({ message: 'User created successfully', user: newUser, token });
    } catch (error) {
        res.status(500).json({ message: 'Error creating user', error: error.message });
    }
};

// Function to log in a user
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Compare the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate a JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'User logged in successfully', token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
};

exports.changePassword = async (req, res) => {
    const { email, oldPassword, newPassword, confirmPassword } = req.body;

    try {
        // Validate that newPassword and confirmPassword match
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'New password and confirm password do not match' });
        }

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Compare the old password
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Old password is incorrect' });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Error changing password:', error.message);
        res.status(500).json({ message: 'Error changing password', error: error.message });
    }
};

// Function to fetch user data by ID
exports.getUserData = async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user data', error: error.message });
    }
};

// Function to edit an existing user
exports.editUser = async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, imei, password } = req.body;
        
        // Find the user by ID
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Update user fields if provided
        if (name) user.name = name;
        if (email) user.email = email;
        if (imei) user.imei = Array.isArray(imei) ? imei : [imei]; // Ensure IMEI is stored as an array
        
        // If password is being updated, hash it
        if (password) {
            user.password = await bcrypt.hash(password, 10);
        }
        
        // Save updated user
        await user.save();
        
        res.status(200).json({ 
            message: 'User updated successfully', 
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                imei: user.imei,
                type: user.type,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ message: 'Error updating user', error: error.message });
    }
};

// Function to fetch device data for a user
exports.getUserbyID = async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user devices', error: error.message });
    }
};

// Function to get device data from BodyTrace API
exports.getDeviceData = async (req, res) => {
    try {
        const { imeis } = req.body; // Accept IMEIs as an array in the request body
        const { limit, from, _, timezone } = req.query;

        // Validate IMEIs
        if (!Array.isArray(imeis) || imeis.some(imei => !/^\d{15}$/.test(imei))) {
            return res.status(400).json({ error: 'Invalid IMEI format. Ensure all IMEIs are 15-digit numbers.' });
        }

        // Get credentials from environment variables
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

        const allDeviceData = [];

        // Fetch data for each IMEI
        for (const imei of imeis) {
            const response = await axios.get(
                `https://us.data.bodytrace.com/1/device/${imei}/datamessages`,
                {
                    params: {
                        limit: limit || 50,
                        from: from || 1,
                        _: _ || Date.now()
                    },
                    headers: {
                        'Authorization': `Basic ${authToken}`,
                        'Accept': 'application/json',
                        'User-Agent': 'Your-App-Name/1.0',
                        'Origin': 'https://console.bodytrace.com',
                        'Referer': 'https://console.bodytrace.com/'
                    }
                }
            );

            console.log(`Data for IMEI ${imei}:`, response.data);

            // Process the response to include human-readable date-time and additional data
            const processedData = response.data.map(entry => ({
                ...entry,
                imei, // Include the IMEI in the response
                dateTime: timezone ? moment(entry.ts).tz(timezone).format() : new Date(entry.ts).toISOString(),
                batteryVoltage: entry.batteryVoltage,
                signalStrength: entry.signalStrength,
                rssi: entry.rssi,
                deviceId: entry.deviceId
            }));

            allDeviceData.push(...processedData);
        }

        // Sort the combined data by timestamp (latest first)
        const sortedData = allDeviceData.sort((a, b) => b.ts - a.ts);

        res.status(200).json(sortedData);
    } catch (error) {
        console.error('Error fetching device data:', error);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error || 'Error fetching device data'
        });
    }
};

// Function to list users with pagination, sorting, and filtering
exports.listUsers = async (req, res) => {
    try {
        const { page = 1, limit = 10, sortBy = 'name', order = 'asc', search = '' } = req.body;

        // Convert `page` and `limit` to numbers
        const pageNumber = parseInt(page, 10);
        const limitNumber = parseInt(limit, 10);

        // Build the query for filtering
        const query = search
            ? { $or: [{ name: { $regex: search, $options: 'i' } }, { email: { $regex: search, $options: 'i' } }] }
            : {};

        // Calculate the total number of users
        const totalUsers = await User.countDocuments(query);

        // Fetch users with pagination, sorting, and filtering
        const users = await User.find(query)
            .sort({ [sortBy]: order === 'asc' ? 1 : -1 }) // Sort by the specified field
            .skip((pageNumber - 1) * limitNumber) // Skip users for pagination
            .limit(limitNumber); // Limit the number of users per page

        res.status(200).json({
            totalUsers,
            totalPages: Math.ceil(totalUsers / limitNumber),
            currentPage: pageNumber,
            users,
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
};

exports.getFilteredDeviceData = async (req, res) => {
    try {
        const { imeis } = req.body; // Accept IMEIs as an array in the request body
        const { startDate, endDate, page = 1, limit = 10, sortBy = 'ts', order = 'desc' } = req.body; // Default order to 'desc'

        console.log('Request Parameters:', { imeis, startDate, endDate, page, limit, sortBy, order });

        // Validate IMEIs
        if (!Array.isArray(imeis) || imeis.some(imei => !/^\d{15}$/.test(imei))) {
            return res.status(400).json({ error: 'Invalid IMEI format. Ensure all IMEIs are 15-digit numbers.' });
        }

        // Get credentials from environment variables
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

        const allFilteredData = [];

        // Fetch and filter data for each IMEI
        for (const imei of imeis) {
            const params = {};
            if (startDate && endDate) {
                const startTimestamp = new Date(startDate).getTime();
                const endTimestamp = new Date(endDate).getTime();

                if (isNaN(startTimestamp) || isNaN(endTimestamp)) {
                    return res.status(400).json({ error: 'Invalid date format' });
                }

                params.from = startTimestamp;
                params.to = endTimestamp;
            }

            const response = await axios.get(
                `https://us.data.bodytrace.com/1/device/${imei}/datamessages`,
                {
                    params,
                    headers: {
                        'Authorization': `Basic ${authToken}`,
                        'Accept': 'application/json',
                        'User-Agent': 'Your-App-Name/1.0',
                        'Origin': 'https://console.bodytrace.com',
                        'Referer': 'https://console.bodytrace.com/',
                    },
                }
            );

            console.log(`Data for IMEI ${imei}:`, response.data);

            // Process and filter the response
            const processedData = response.data.map(entry => ({
                ...entry,
                imei, // Include the IMEI in the response
                dateTime: new Date(entry.ts).toISOString(),
            }));

            const filteredData = processedData.filter(entry => entry.values && entry.values.weight !== undefined);

            allFilteredData.push(...filteredData);
        }

        // Sort the combined data (latest first)
        const sortedData = allFilteredData.sort((a, b) => {
            if (order === 'asc') {
                return a[sortBy] > b[sortBy] ? 1 : -1;
            } else {
                return a[sortBy] < b[sortBy] ? 1 : -1;
            }
        });

        // Apply pagination
        const offset = (page - 1) * limit;
        const paginatedData = sortedData.slice(offset, offset + limit);

        res.status(200).json({
            totalCount: allFilteredData.length,
            totalPages: Math.ceil(allFilteredData.length / limit),
            currentPage: page,
            data: paginatedData,
        });
    } catch (error) {
        console.error('Error fetching filtered device data:', error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error || 'Error fetching filtered device data',
        });
    }
};


exports.generateDeviceDataCsv = async (req, res) => {
    try {
        const { imeis } = req.body; // Accept IMEIs as an array in the request body
        const { startDate, endDate, page = 1, limit = 10, sortBy = 'ts', order = 'asc' } = req.body;

        console.log('Request Parameters:', { imeis, startDate, endDate, page, limit, sortBy, order });

        // Validate IMEIs
        if (!Array.isArray(imeis) || imeis.some(imei => !/^\d{15}$/.test(imei))) {
            console.error('Invalid IMEI format:', imeis);
            return res.status(400).json({ error: 'Invalid IMEI format. Ensure all IMEIs are 15-digit numbers.' });
        }

        // Get credentials from environment variables
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

        console.log('Auth Token Generated');

        const allFilteredData = [];

        // Fetch and process data for each IMEI
        for (const imei of imeis) {
            const params = {};
            if (startDate && endDate) {
                const startTimestamp = new Date(startDate).getTime();
                const endTimestamp = new Date(endDate).getTime();

                if (isNaN(startTimestamp) || isNaN(endTimestamp)) {
                    console.error('Invalid date format:', { startDate, endDate });
                    return res.status(400).json({ error: 'Invalid date format' });
                }

                params.from = startTimestamp;
                params.to = endTimestamp;

                console.log('Date Range:', { startTimestamp, endTimestamp });
            }

            console.log(`Fetching data for IMEI: ${imei}`);

            const response = await axios.get(
                `https://us.data.bodytrace.com/1/device/${imei}/datamessages`,
                {
                    params,
                    headers: {
                        'Authorization': `Basic ${authToken}`,
                        'Accept': 'application/json',
                        'User-Agent': 'Your-App-Name/1.0',
                        'Origin': 'https://console.bodytrace.com',
                        'Referer': 'https://console.bodytrace.com/',
                    },
                }
            );

            console.log(`API Response Data for IMEI ${imei}:`, response.data);

            // Process the response to include human-readable date-time and additional data
            const processedData = response.data.map(entry => ({
                imei, // Include the IMEI in the response
                dateTime: new Date(entry.ts).toISOString(),
                batteryVoltage: entry.batteryVoltage,
                signalStrength: entry.signalStrength,
                rssi: entry.rssi,
                deviceId: entry.deviceId,
                weight: entry.values?.weight,
                unit: entry.values?.unit,
                tare: entry.values?.tare,
            }));

            console.log(`Processed Data for IMEI ${imei}:`, processedData);

            // Filter data to include only entries with the `values` field
            const filteredData = processedData.filter(entry => entry.weight !== undefined);

            console.log(`Filtered Data for IMEI ${imei}:`, filteredData);

            allFilteredData.push(...filteredData);
        }

        // Sort the combined data
        const sortedData = allFilteredData.sort((a, b) => {
            if (order === 'asc') {
                return a[sortBy] > b[sortBy] ? 1 : -1;
            } else {
                return a[sortBy] < b[sortBy] ? 1 : -1;
            }
        });

        console.log('Sorted Data:', sortedData);

        // Apply pagination to the sorted data
        const offset = (page - 1) * limit;
        const paginatedData = sortedData.slice(offset, offset + limit);

        console.log('Paginated Data for CSV:', paginatedData);

        // Generate CSV
        const fields = ['imei', 'dateTime', 'batteryVoltage', 'signalStrength', 'rssi', 'deviceId', 'weight', 'unit', 'tare'];
        const opts = { fields };
        const parser = new Parser(opts);
        const csv = parser.parse(paginatedData);

        console.log('CSV Generated Successfully');

        // Send the CSV file as a response
        res.header('Content-Type', 'text/csv');
        res.attachment(`device_data_page_${page}.csv`);
        res.send(csv);
    } catch (error) {
        console.error('Error generating CSV for device data:', error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error || 'Error generating CSV for device data',
        });
    }
};
exports.requestPasswordReset = async (req, res) => {
    const { email } = req.body;

    try {
        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate a reset token (valid for 1 hour)
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

        // Save the reset token and expiry to the user's record
        user.resetToken = resetToken;
        user.resetTokenExpiry = resetTokenExpiry;
        await user.save();

        // Send the reset link via email
        const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        const transporter = nodemailer.createTransport({
            service: 'Gmail', // Use your email service
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            html: `<p>You requested a password reset. Click the link below to reset your password:</p>
                   <a href="${resetLink}">${resetLink}</a>
                   <p>If you did not request this, please ignore this email.</p>`,
        });

        res.status(200).json({ message: 'Password reset link sent to your email.' });
    } catch (error) {
        console.error('Error requesting password reset:', error.message);
        res.status(500).json({ message: 'Error requesting password reset', error: error.message });
    }
};

exports.resetPassword = async (req, res) => {
    const { resetToken, newPassword, confirmPassword } = req.body;

    try {
        // Validate passwords
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }

        // Find the user by reset token and check if the token is still valid
        const user = await User.findOne({
            resetToken,
            resetTokenExpiry: { $gt: Date.now() }, // Ensure the token has not expired
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password and clear the reset token
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error.message);
        res.status(500).json({ message: 'Error resetting password', error: error.message });
    }
};