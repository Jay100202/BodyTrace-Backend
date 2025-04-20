const MiddleAdmin = require('../models/middleAdmin'); // Import the MiddleAdmin model
const User = require('../models/User');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const moment = require('moment-timezone'); // For timezone handling
const crypto = require('crypto'); // For generating random tokens

exports.createMiddleAdminsFromExcel = async (req, res) => {
    try {
        // Check if a file is uploaded
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        // Ensure the uploads directory exists
        const uploadsDir = path.join(__dirname, '../uploads');
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir);
        }

        // Read the uploaded Excel file
        const filePath = req.file.path;
        const workbook = xlsx.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = xlsx.utils.sheet_to_json(sheet);

        // Process each row in the Excel file
        const updatedData = [];
        let counter = 1; // Counter to generate sequential email

        // Function to generate a random 8-character password
        const generateRandomPassword = () => {
            return crypto.randomBytes(4).toString('hex').slice(0, 8); // Generate a random 8-character string
        };

        for (const row of data) {
            const name = row.name; // Assuming the column name is "name"
            const imeis = row.imeis; // Assuming the column name is "imeis" (comma-separated IMEIs)

            if (!name || !imeis) {
                continue; // Skip rows without a name or IMEIs
            }

            // Split the IMEIs into an array and validate them
            const assignedImeis = imeis.split(',').map(imei => imei.trim());
            if (assignedImeis.some(imei => !/^\d{15}$/.test(imei))) {
                console.error(`Invalid IMEI format in row: ${JSON.stringify(row)}`);
                continue; // Skip rows with invalid IMEI formats
            }

            // Generate email and password
            const email = `middleadmin${counter}@gmail.com`; // Sequential email
            const password = generateRandomPassword(); // Generate a random 8-character password

            // Save the middle admin to the database
            const newMiddleAdmin = new MiddleAdmin({ name, email, password, imeis: assignedImeis });
            await newMiddleAdmin.save();

            // Add the generated data to the output
            updatedData.push({ Name: name, Email: email, Password: password, IMEIs: assignedImeis.join(', ') });
            counter++; // Increment the counter for the next middle admin
        }

        // Create a new Excel file with the updated data
        const newSheet = xlsx.utils.json_to_sheet(updatedData);
        const newWorkbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Middle Admins');

        const outputPath = path.join(uploadsDir, 'middle_admins.xlsx');
        xlsx.writeFile(newWorkbook, outputPath);

        // Send the updated Excel file as a response
        res.download(outputPath, 'middle_admins.xlsx', (err) => {
            if (err) {
                console.error('Error sending file:', err);
                res.status(500).json({ message: 'Error sending file' });
            }

            // Delete the temporary files
            fs.unlinkSync(filePath);
            fs.unlinkSync(outputPath);
        });
    } catch (error) {
        console.error('Error processing Excel file:', error.message);
        res.status(500).json({ message: 'Error processing Excel file', error: error.message });
    }
};


exports.getUsersByMiddleAdminEmail = async (req, res) => {
    try {
        const { email } = req.params; // Middle admin email from the request parameters

        console.log('Fetching users for middle admin with email:', email); // Log the email being processed
        const { page = 1, limit = 10, sortBy = 'createdAt', order = 'desc' } = req.query; // Pagination and sorting options

        // Find the middle admin by email
        const middleAdmin = await MiddleAdmin.findOne({ email });
        if (!middleAdmin) {
            return res.status(404).json({ message: 'Middle admin not found' });
        }

        // Get the IMEIs assigned to the middle admin
        const assignedImeis = middleAdmin.imeis;

        // Fetch users assigned to the IMEIs
        const query = { imei: { $in: assignedImeis } };
        const totalCount = await User.countDocuments(query); // Total number of users
        const users = await User.find(query)
            .select('-password') // Exclude the password field
            .sort({ [sortBy]: order === 'asc' ? 1 : -1 }) // Sort by the specified field
            .skip((page - 1) * limit) // Skip for pagination
            .limit(parseInt(limit)); // Limit the number of results

        // Fetch the last reported data for each IMEI
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

        const usersWithLastReportedData = await Promise.all(
            users.map(async (user) => {
                try {
                    const response = await axios.get(
                        `https://us.data.bodytrace.com/1/device/${user.imei}/datamessages`,
                        {
                            headers: {
                                'Authorization': `Basic ${authToken}`,
                                'Accept': 'application/json',
                                'User-Agent': 'Your-App-Name/1.0',
                                'Origin': 'https://console.bodytrace.com',
                                'Referer': 'https://console.bodytrace.com/',
                            },
                        }
                    );

            

                    // Filter the data to include only entries with the `values` field
                    const filteredData = response.data.filter(entry => entry.values);


                    // Get the last entry with the `values` field or null if no such entry exists
                    const lastReportedData = filteredData.length > 0 ? filteredData[0] : null;

                    return {
                        ...user.toObject(),
                        lastReportedData, // Include the last reported data
                    };
                } catch (error) {
                    console.error(`Error fetching last reported data for IMEI ${user.imei}:`, error.message);
                    return {
                        ...user.toObject(),
                        lastReportedData: null, // Include null if there's an error
                    };
                }
            })
        );

        // Respond with the paginated data including last reported data
        res.status(200).json({
            totalCount,
            totalPages: Math.ceil(totalCount / limit),
            currentPage: parseInt(page),
            data: usersWithLastReportedData,
        });
    } catch (error) {
        console.error('Error fetching users by middle admin email:', error.message);
        res.status(500).json({ message: 'Error fetching users by middle admin email', error: error.message });
    }
};


exports.loginMiddleAdmin = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the middle admin by email
        const middleAdmin = await MiddleAdmin.findOne({ email });
        if (!middleAdmin) {
            return res.status(404).json({ message: 'Middle admin not found' });
        }

        // Directly compare the plain text password
        if (middleAdmin.password !== password) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        // Respond with middle admin details
        res.status(200).json({
            message: 'Middle admin logged in successfully',
            data: {
                name: middleAdmin.name,
                email: middleAdmin.email,
                type: 'middleAdmin', // Static type field
                imeis: middleAdmin.imeis, // Assigned IMEIs
                createdAt: middleAdmin.createdAt,
                updatedAt: middleAdmin.updatedAt,
            },
        });
    } catch (error) {
        console.error('Error logging in middle admin:', error.message);
        res.status(500).json({ message: 'Error logging in middle admin', error: error.message });
    }
};


exports.getDeviceData = async (req, res) => {
    try {
        const { imei } = req.body; // Extract the IMEI from the request body
        const { limit = 50, from = 1, timezone } = req.query; // Query parameters for pagination and timezone

        // Validate the IMEI
        if (!imei || !/^\d{15}$/.test(imei)) {
            return res.status(400).json({ error: 'Invalid IMEI format. Ensure the IMEI is a 15-digit number.' });
        }

        // Get credentials from environment variables
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

        // Fetch data for the IMEI
        const response = await axios.get(
            `https://us.data.bodytrace.com/1/device/${imei}/datamessages`,
            {
                params: {
                    limit: parseInt(limit), // Limit the number of results
                    from: parseInt(from), // Start timestamp
                    _: Date.now() // Cache-busting parameter
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

        // Sort the data by timestamp (latest first)
        const sortedData = processedData.sort((a, b) => b.ts - a.ts);

        res.status(200).json(sortedData);
    } catch (error) {
        console.error('Error fetching device data:', error.message);
        res.status(error.response?.status || 500).json({
            error: error.response?.data?.error || 'Error fetching device data'
        });
    }
};