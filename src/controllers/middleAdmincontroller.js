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
        console.log('Starting createMiddleAdminsFromExcel process');
        
        // Check if a file is uploaded
        if (!req.file) {
            console.log('No file uploaded');
            return res.status(400).json({ message: 'No file uploaded' });
        }
        
        console.log('File uploaded successfully:', req.file.originalname);

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
        console.log(`Excel file read successfully. Found ${data.length} rows of data.`);

        // Group data by name and organization to handle vertical IMEIs
        const groupedData = {};
        let currentKey = null; // Track the current name-organization pair
        let currentName = null;
        let currentOrg = null;
        
        for (const row of data) {
            const name = row.name;
            const imei = row.imeis; // Each row has a single IMEI in the 'imeis' column
            const organization = row.organization;
            
            if (!imei) {
                console.log('Skipping row with no IMEI:', JSON.stringify(row));
                continue;
            }
            
            // Convert any non-string IMEI to string and clean it
            const cleanImei = String(imei).trim().replace(/\..*$/, ''); // Remove decimal points
            
            // Validate IMEI format
            if (!/^\d{15}$/.test(cleanImei)) {
                console.error(`Invalid IMEI format: ${imei}, cleaned to: ${cleanImei}`);
                continue;
            }

            // If name is present, update current name and org
            if (name) {
                currentName = name;
                currentOrg = organization || 'Default Organization';
                // Create a unique key for each name + organization pair
                currentKey = `${currentName}-${currentOrg}`;
                
                if (!groupedData[currentKey]) {
                    console.log(`Creating new group for ${currentName} in ${currentOrg}`);
                    groupedData[currentKey] = {
                        name: currentName,
                        organization: currentOrg,
                        imeis: []
                    };
                }
            } else if (!currentKey) {
                // If there's no current key and no name in this row, we can't process this IMEI
                console.log('Cannot process IMEI without a preceding name:', cleanImei);
                continue;
            }
            
            // Add IMEI to the current group if not already in the array
            if (!groupedData[currentKey].imeis.includes(cleanImei)) {
                console.log(`Adding IMEI ${cleanImei} to ${currentName} in ${currentOrg}`);
                groupedData[currentKey].imeis.push(cleanImei);
            }
        }

        console.log(`Grouped data into ${Object.keys(groupedData).length} name-organization pairs`);
        
        // Process each grouped entry
        const updatedData = [];
        let counter = await MiddleAdmin.countDocuments() + 1;
        
        const generateRandomPassword = () => {
            return crypto.randomBytes(4).toString('hex').slice(0, 8);
        };
        
        for (const key in groupedData) {
            const { name, organization, imeis } = groupedData[key];
            console.log(`Processing ${name} with ${imeis.length} IMEIs in organization ${organization}`);
            
            // Check if this admin with the same name and organization already exists
            const existingAdmin = await MiddleAdmin.findOne({ name, organization });
            
            let adminEmail, adminPassword, adminStatus;
            let finalImeis;
            
            if (existingAdmin) {
                console.log(`Found existing admin: ${name} in ${organization}`);
                
                // Merge IMEIs and remove duplicates
                finalImeis = [...new Set([...existingAdmin.imeis, ...imeis])];
                
                // Update the admin record
                existingAdmin.imeis = finalImeis;
                await existingAdmin.save();
                
                adminEmail = existingAdmin.email;
                adminPassword = existingAdmin.password; // Use actual password, not masked
                adminStatus = "Updated";
                
                console.log(`Updated ${name} with ${finalImeis.length} IMEIs`);
            } else {
                // Create new middle admin
                adminEmail = `middleadmin${counter}@gmail.com`;
                adminPassword = generateRandomPassword();
                adminStatus = "Created";
                finalImeis = imeis;
                
                const newMiddleAdmin = new MiddleAdmin({
                    name,
                    email: adminEmail,
                    password: adminPassword,
                    organization,
                    imeis: finalImeis
                });
                
                await newMiddleAdmin.save();
                console.log(`Created new middle admin: ${name} with email ${adminEmail}`);
                counter++;
            }
            
            // Add each IMEI as a separate row in the output data
            for (const imei of finalImeis) {
                updatedData.push({
                    Name: name,
                    Organization: organization,
                    Email: adminEmail,
                    Password: adminPassword, // Now showing actual password
                    IMEI: imei,
                    Status: adminStatus
                });
            }
        }

        console.log(`Processing complete. Created output data with ${updatedData.length} rows`);

        // Create a new Excel file with the updated data
        const newSheet = xlsx.utils.json_to_sheet(updatedData);
        const newWorkbook = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(newWorkbook, newSheet, 'Middle Admins');

        const outputPath = path.join(uploadsDir, 'middle_admins.xlsx');
        xlsx.writeFile(newWorkbook, outputPath);
        console.log(`Output Excel file created at: ${outputPath}`);

        // Send the updated Excel file as a response
        console.log('Sending file as download response');
        res.download(outputPath, 'client.xlsx', (err) => {
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