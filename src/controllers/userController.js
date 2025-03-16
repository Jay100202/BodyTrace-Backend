const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Function to create a new user
exports.createUser = async (req, res) => {
    const { name, email, password, imei } = req.body;

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ name, email, password: hashedPassword, imei });
        await newUser.save();

        // Generate a JWT token
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

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

// Function to fetch device data for a user
exports.getUserDevices = async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findById(id).populate('devices');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json(user.devices);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching user devices', error: error.message });
    }
};

// Function to get device data from BodyTrace API
exports.getDeviceData = async (req, res) => {
    try {
        const { imei } = req.params;
        const { limit, from, _, timezone } = req.query;

        // Validate IMEI (15 digits)
        if (!/^\d{15}$/.test(imei)) {
            return res.status(400).json({ error: 'Invalid IMEI format' });
        }

        // Get credentials from environment variables
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

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

        console.log('Proxy response:', response.data);

        // Process the response to include human-readable date-time and additional data
        const processedData = response.data.map(entry => ({
            ...entry,
            dateTime: timezone ? moment(entry.ts).tz(timezone).format() : new Date(entry.ts).toISOString(),
            batteryVoltage: entry.batteryVoltage,
            signalStrength: entry.signalStrength,
            rssi: entry.rssi,
            deviceId: entry.deviceId
        }));

        // Forward the processed response
        res.json(processedData);

    } catch (error) {
        console.error('Proxy error:', error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error || 'Proxy error'
        });
    }
};