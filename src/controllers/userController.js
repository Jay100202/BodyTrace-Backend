const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const axios = require('axios'); // Import axios for making HTTP requests
const crypto = require('crypto'); // For generating random tokens
const nodemailer = require('nodemailer'); // For sending emails
const { Parser } = require('json2csv'); // Import json2csv for CSV generation
// Function to create a new user

const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const path = require('path');


// Configure multer for file uploads
const upload = multer({ dest: 'uploads/' });


exports.createUsersFromExcel = async (req, res) => {
    try {
        console.log('Starting createUsersFromExcel process');
        
        // Check if a file is uploaded
        if (!req.file) {
            console.log('No file uploaded');
            return res.status(400).json({ message: 'No file uploaded' });
        }
        
        console.log('File uploaded successfully:', req.file.originalname);

        // Ensure the uploads directory exists
        const uploadsDir = path.join(__dirname, '../uploads');
        if (!fs.existsSync(uploadsDir)) {
            console.log('Creating uploads directory');
            fs.mkdirSync(uploadsDir);
        }

        // Read the uploaded Excel file
        const filePath = req.file.path;
        const workbook = xlsx.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = xlsx.utils.sheet_to_json(sheet);
        console.log(`Excel file read successfully. Found ${data.length} rows of data.`);

        // Get domain-specific counters
        const domainCounters = {};
        const domains = [...new Set(data.map(row => row['email domain']).filter(Boolean))];
        
        console.log(`Found ${domains.length} unique domains in input file`);
        
        // Initialize counters for each domain
        for (const domain of domains) {
            try {
                // Get all existing users with this domain to find the highest counter
                const regex = new RegExp(`^escale(\\d+)@${domain.replace(/\./g, '\\.')}$`, 'i');
                const existingUsers = await User.find({ email: { $regex: regex } });
                
                console.log(`Found ${existingUsers.length} existing users for domain ${domain}`);
                
                // Find the highest counter
                let highestCounter = 0;
                for (const user of existingUsers) {
                    const match = user.email.match(/escale(\d+)@/i);
                    if (match && match[1]) {
                        const counter = parseInt(match[1], 10);
                        if (counter > highestCounter) {
                            highestCounter = counter;
                        }
                    }
                }
                
                // Start from the next available counter
                domainCounters[domain] = highestCounter + 1;
                
                console.log(`Initialized counter for ${domain} at ${domainCounters[domain]}`);
            } catch (error) {
                console.error(`Error finding highest counter for ${domain}:`, error);
                domainCounters[domain] = 1; // Default to 1 if there's an error
            }
        }

        // Function to generate a secure 12-character password
        const generateRandomPassword = () => {
            const lowerCaseChars = 'abcdefghijklmnopqrstuvwxyz';
            const upperCaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            const numbers = '0123456789';
            const specialChars = '!@#$%^&*_-+=';
            
            // Ensure at least one of each type
            let password = '';
            password += lowerCaseChars[Math.floor(Math.random() * lowerCaseChars.length)];
            password += upperCaseChars[Math.floor(Math.random() * upperCaseChars.length)];
            password += numbers[Math.floor(Math.random() * numbers.length)];
            password += specialChars[Math.floor(Math.random() * specialChars.length)];
            
            // Fill the rest of the password (8 more characters)
            const allChars = lowerCaseChars + upperCaseChars + numbers + specialChars;
            for (let i = 0; i < 8; i++) {
                password += allChars[Math.floor(Math.random() * allChars.length)];
            }
            
            // Shuffle the password characters
            return password.split('').sort(() => 0.5 - Math.random()).join('');
        };

        // Create a set to track which IMEIs have been processed
        const processedIMEIs = new Set();
        
        // Process each row in the Excel file
        const updatedData = [];
        for (const row of data) {
            const imei = String(row.imei).trim(); // Convert to string and trim
            const domain = row['email domain']; // Get domain from Excel
            
            console.log(`Processing row: IMEI=${imei}, Domain=${domain}`);
            
            if (!imei || isNaN(Number(imei))) { // Validate that IMEI is a number
                console.log(`Skipping row with invalid IMEI: ${imei}`);
                updatedData.push({ 
                    IMEI: imei || 'Invalid', 
                    Email: 'N/A', 
                    Password: 'N/A',
                    Status: 'Skipped - Invalid IMEI' 
                });
                continue; // Skip invalid IMEI rows
            }

            if (!domain) {
                console.log(`Skipping row with missing domain: IMEI=${imei}`);
                updatedData.push({ 
                    IMEI: imei, 
                    Email: 'N/A', 
                    Password: 'N/A',
                    Status: 'Skipped - Missing Domain' 
                });
                continue; // Skip rows without domain
            }

            // Skip duplicate IMEIs in the same file
            if (processedIMEIs.has(imei)) {
                console.log(`Skipping duplicate IMEI in the file: ${imei}`);
                updatedData.push({ 
                    IMEI: imei, 
                    Email: 'N/A', 
                    Password: 'N/A',
                    Status: 'Skipped - Duplicate IMEI in file' 
                });
                continue;
            }

            // Mark this IMEI as processed
            processedIMEIs.add(imei);

            try {
                // Check if the IMEI already exists in the database
                const existingUser = await User.findOne({ imei });

                if (existingUser) {
                    console.log(`Found existing user for IMEI ${imei}: ${existingUser.email}`);
                    // If the IMEI already exists, include its existing email and password in the output
                    updatedData.push({ 
                        IMEI: imei, 
                        Email: existingUser.email, 
                        Password: existingUser.password,
                        Status: 'Existing' 
                    });
                } else {
                    // Generate new user with unique email
                    let emailCreated = false;
                    let attempts = 0;
                    let email, password;
                    
                    while (!emailCreated && attempts < 10) {
                        // Generate new user credentials using the domain-specific counter
                        const currentCounter = domainCounters[domain];
                        email = `escale${currentCounter}@${domain}`;
                        password = generateRandomPassword();
                        
                        console.log(`Attempting to create user with email: ${email}`);
                        
                        // Check if email already exists
                        const emailExists = await User.findOne({ email });
                        
                        if (emailExists) {
                            console.log(`Email ${email} already exists, incrementing counter`);
                            domainCounters[domain] = currentCounter + 1;
                            attempts++;
                        } else {
                            emailCreated = true;
                        }
                    }
                    
                    if (!emailCreated) {
                        console.log(`Failed to create unique email for IMEI ${imei} after ${attempts} attempts`);
                        updatedData.push({ 
                            IMEI: imei, 
                            Email: 'N/A', 
                            Password: 'N/A',
                            Status: 'Error - Could not generate unique email' 
                        });
                        continue;
                    }
                    
                    console.log(`Creating new user for IMEI ${imei}: ${email}`);

                    // Save the new user to the database
                    const newUser = new User({ 
                        name: email, 
                        email, 
                        password, 
                        imei,
                        type: "user"
                    });
                    
                    await newUser.save();

                    // Add the new user's credentials to the output
                    updatedData.push({ 
                        IMEI: imei, 
                        Email: email, 
                        Password: password,
                        Status: 'Created' 
                    });
                    
                    // Increment the domain-specific counter
                    domainCounters[domain] = domainCounters[domain] + 1;
                    console.log(`Updated counter for ${domain} to ${domainCounters[domain]}`);
                }
            } catch (error) {
                console.error(`Error processing IMEI ${imei}:`, error);
                updatedData.push({ 
                    IMEI: imei, 
                    Email: 'N/A', 
                    Password: 'N/A',
                    Status: `Error - ${error.message}` 
                });
            }
        }

        console.log(`Processing complete. Created output data with ${updatedData.length} rows`);

        // Create a new Excel file with the updated data
        const newSheet = xlsx.utils.json_to_sheet(updatedData);
        const newWorkbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Updated Data');

        const outputPath = path.join(uploadsDir, 'updated_users.xlsx');
        xlsx.writeFile(newWorkbook, outputPath);
        console.log(`Output Excel file created at: ${outputPath}`);

        // Send the updated Excel file as a response
        console.log('Sending file as download response');
        res.download(outputPath, 'updated_users.xlsx', (err) => {
            if (err) {
                console.error('Error sending file:', err);
                res.status(500).json({ message: 'Error sending file' });
            } else {
                console.log('File sent successfully');
            }

            // Delete the temporary files
            console.log('Cleaning up temporary files');
            fs.unlinkSync(filePath);
            fs.unlinkSync(outputPath);
            console.log('Temporary files deleted');
        });
    } catch (error) {
        console.error('Error processing Excel file:', error);
        console.error('Error details:', error.message);
        console.error('Error stack:', error.stack);
        res.status(500).json({ message: 'Error processing Excel file', error: error.message });
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

        // Update the last login time
        user.lastLogin = new Date();
        await user.save();

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
        const { imei } = req.body; // Accept a single IMEI in the request body
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
        const { imei, search = '' } = req.body; // Added search parameter
        const { startDate, endDate, page = 1, limit = 10, sortBy = 'ts', order = 'desc' } = req.body;
        
        console.log("request body:", req.body);
        console.log('Request Parameters:', { imei, startDate, endDate, page, limit, sortBy, order, search });

        // Add detailed logging for search
        console.log('=== DEVICE DATA SEARCH DEBUG INFO ===');
        console.log('Search parameter received:', search);
        console.log('Search type:', typeof search);
        console.log('Search length:', search ? search.length : 0);
        console.log('Search after trim:', search ? search.trim() : 'empty');
        console.log('Is search truthy?', !!search);
        console.log('Is search not empty after trim?', search && search.trim() !== '');
        console.log('=====================================');

        // Validate the IMEI
        if (!imei || !/^\d{15}$/.test(imei)) {
            return res.status(400).json({ error: 'Invalid IMEI format. Ensure the IMEI is a 15-digit number.' });
        }

        // Get credentials from environment variables
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

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

        // Fetch data for the IMEI
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

        console.log(`Data fetched from API for IMEI ${imei}:`, response.data.length, 'entries');

        // Process and filter the response
        const processedData = response.data.map(entry => ({
            ...entry,
            imei,
            dateTime: new Date(entry.ts).toISOString(),
        }));

        console.log('Processed data entries:', processedData.length);

        // Filter data to include only entries with weight values
        let filteredData = processedData.filter(entry => entry.values && entry.values.weight !== undefined);
        console.log('Entries with weight values:', filteredData.length);

        // Apply search functionality if search term is provided
        if (search && search.trim() !== '') {
            console.log('APPLYING SEARCH FILTER to device data');
            const searchTerm = search.toLowerCase();
            console.log('Search term (lowercase):', searchTerm);
            
            const beforeSearchCount = filteredData.length;
            
            filteredData = filteredData.filter(entry => {
                const imeiMatch = entry.imei.toString().includes(searchTerm);
                const dateTimeMatch = entry.dateTime.toLowerCase().includes(searchTerm);
                const weightMatch = entry.values.weight.toString().includes(searchTerm);
                const unitMatch = entry.values.unit && entry.values.unit.toString().toLowerCase().includes(searchTerm);
                const deviceIdMatch = entry.deviceId && entry.deviceId.toString().includes(searchTerm);
                const tareMatch = entry.values.tare && entry.values.tare.toString().includes(searchTerm);
                
                const isMatch = imeiMatch || dateTimeMatch || weightMatch || unitMatch || deviceIdMatch || tareMatch;
                
                // Log first few matches for debugging
                if (isMatch && filteredData.indexOf(entry) < 3) {
                    console.log(`Match found in entry:`, {
                        imei: imeiMatch,
                        dateTime: dateTimeMatch,
                        weight: weightMatch,
                        unit: unitMatch,
                        deviceId: deviceIdMatch,
                        tare: tareMatch,
                        values: entry.values
                    });
                }
                
                return isMatch;
            });
            
            console.log(`Search results: ${beforeSearchCount} -> ${filteredData.length} entries`);
        } else {
            console.log('NO SEARCH FILTER APPLIED - using all weight data');
        }

        // Sort the combined data
        const sortedData = filteredData.sort((a, b) => {
            if (order === 'asc') {
                return a[sortBy] > b[sortBy] ? 1 : -1;
            } else {
                return a[sortBy] < b[sortBy] ? 1 : -1;
            }
        });

        console.log('Data sorted by:', sortBy, order);

        // Apply pagination
        const offset = (page - 1) * limit;
        const paginatedData = sortedData.slice(offset, offset + limit);

        console.log("=== FINAL DEVICE DATA RESULTS ===");
        console.log("Search term:", `"${search}"`);
        console.log("Total count after search:", filteredData.length);
        console.log("Total pages:", Math.ceil(filteredData.length / limit));
        console.log("Current page:", page);
        console.log("Paginated data entries:", paginatedData.length);
        console.log("===============================");

        res.status(200).json({
            totalCount: filteredData.length,
            totalPages: Math.ceil(filteredData.length / limit),
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
        const { imei } = req.body; // Accept a single IMEI in the request body
        const { startDate, endDate, page = 1, limit = 10, sortBy = 'ts', order = 'asc' } = req.body;

        console.log('Request Parameters:', { imei, startDate, endDate, page, limit, sortBy, order });

        // Validate the IMEI
        if (!imei || !/^\d{15}$/.test(imei)) {
            console.error('Invalid IMEI format:', imei);
            return res.status(400).json({ error: 'Invalid IMEI format. Ensure the IMEI is a 15-digit number.' });
        }

        // Get credentials from environment variables
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

        console.log('Auth Token Generated');

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

        // Sort the filtered data
        const sortedData = filteredData.sort((a, b) => {
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

exports.resetUsersPasswordFromExcel = async (req, res) => {
    try {
        console.log('Starting resetUsersPasswordFromExcel process');
        
        // Check if a file is uploaded
        if (!req.file) {
            console.log('No file uploaded');
            return res.status(400).json({ message: 'No file uploaded' });
        }
        
        console.log('File uploaded successfully:', req.file.originalname);

        // Ensure the uploads directory exists
        const uploadsDir = path.join(__dirname, '../uploads');
        if (!fs.existsSync(uploadsDir)) {
            console.log('Creating uploads directory');
            fs.mkdirSync(uploadsDir);
        }

        // Read the uploaded Excel file
        const filePath = req.file.path;
        const workbook = xlsx.readFile(filePath);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        const data = xlsx.utils.sheet_to_json(sheet);
        console.log(`Excel file read successfully. Found ${data.length} rows of data.`);

        // Function to generate a random 8-character password
        const generateRandomPassword = () => {
            return crypto.randomBytes(4).toString('hex'); // Generates a random 8-character string
        };

        // Process each row in the Excel file
        const updatedData = [];
        for (const row of data) {
            const email = row.email; // Column for email
            const imei = row.imei;   // Column for IMEI (optional)
            
            console.log(`Processing row: Email=${email}, IMEI=${imei}`);
            
            if (!email) {
                console.log('Skipping row due to missing email');
                updatedData.push({ 
                    Email: 'Missing',
                    IMEI: imei || 'N/A', 
                    Status: 'Skipped',
                    Message: 'Email is required',
                    NewPassword: 'N/A'
                });
                continue;
            }
            
            try {
                // Find the user by email
                const user = await User.findOne({ email });
                
                if (!user) {
                    console.log(`User not found with email: ${email}`);
                    updatedData.push({ 
                        Email: email, 
                        IMEI: imei || 'N/A', 
                        Status: 'Error',
                        Message: 'User not found',
                        NewPassword: 'N/A'
                    });
                    continue;
                }
                
                // If IMEI is provided, verify it matches the user's IMEI (convert both to strings for comparison)
                if (imei) {
                    const imeiString = String(imei).trim();
                    const userImeiString = String(user.imei).trim();
                    
                    console.log(`Comparing IMEIs: Input=${imeiString}, Stored=${userImeiString}`);
                    
                    if (imeiString !== userImeiString) {
                        console.log(`IMEI mismatch for user ${email}: Expected ${userImeiString}, got ${imeiString}`);
                        updatedData.push({ 
                            Email: email, 
                            IMEI: imei, 
                            Status: 'Error',
                            Message: `IMEI does not match user record (${userImeiString})`,
                            NewPassword: 'N/A'
                        });
                        continue;
                    }
                }

                // Generate a new password
                const newPassword = generateRandomPassword();
                console.log(`Generated new password for ${email}: ${newPassword}`);
                
                // Update the user's password (using plaintext password, not hashed)
                user.password = newPassword;
                await user.save();
                console.log(`Password updated for user ${email}`);

                // Add the updated user info to the output
                updatedData.push({ 
                    Email: email, 
                    IMEI: user.imei || 'N/A', 
                    Status: 'Success',
                    Message: 'Password reset successfully',
                    NewPassword: newPassword
                });
                
            } catch (err) {
                console.error(`Error processing row for ${email}:`, err.message);
                updatedData.push({ 
                    Email: email, 
                    IMEI: imei || 'N/A', 
                    Status: 'Error',
                    Message: `Error: ${err.message}`,
                    NewPassword: 'N/A'
                });
            }
        }

        console.log(`Processing complete. Total records processed: ${updatedData.length}`);

        // Create a new Excel file with the updated data
        const newSheet = xlsx.utils.json_to_sheet(updatedData);
        const newWorkbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Updated Passwords');

        const outputPath = path.join(uploadsDir, 'updated_passwords.xlsx');
        xlsx.writeFile(newWorkbook, outputPath);
        console.log(`Output Excel file created at: ${outputPath}`);

        // Send the updated Excel file as a response
        console.log('Sending file as download response');
        res.download(outputPath, 'updated_passwords.xlsx', (err) => {
            if (err) {
                console.error('Error sending file:', err);
                res.status(500).json({ message: 'Error sending file' });
            } else {
                console.log('File sent successfully');
            }

            // Delete the temporary files
            console.log('Cleaning up temporary files');
            fs.unlinkSync(filePath);
            fs.unlinkSync(outputPath);
            console.log('Temporary files deleted');
        });
    } catch (error) {
        console.error('Error processing Excel file:', error);
        console.error('Error details:', error.message);
        console.error('Error stack:', error.stack);
        res.status(500).json({ message: 'Error processing Excel file', error: error.message });
    }
};