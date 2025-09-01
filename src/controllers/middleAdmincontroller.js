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
        let currentEmail = null;
        
        for (const row of data) {
            const name = row.name;
            const imei = row.imeis; // Each row has a single IMEI in the 'imeis' column
            const organization = row.organization;
            const email = row.email; // Get email from Excel sheet
            
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

            // If name is present, update current name, org and email
            if (name) {
                currentName = name;
                currentOrg = organization || 'Default Organization';
                currentEmail = email || null; // Use provided email or null
                // Create a unique key for each name + organization pair
                currentKey = `${currentName}-${currentOrg}`;
                
                if (!groupedData[currentKey]) {
                    console.log(`Creating new group for ${currentName} in ${currentOrg} with email ${currentEmail || 'not provided'}`);
                    groupedData[currentKey] = {
                        name: currentName,
                        organization: currentOrg,
                        email: currentEmail,
                        imeis: []
                    };
                } else if (email && !groupedData[currentKey].email) {
                    // Update email if it wasn't provided before but is now
                    console.log(`Updating email for ${currentName} to ${email}`);
                    groupedData[currentKey].email = email;
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
        
        for (const key in groupedData) {
            const { name, organization, email, imeis } = groupedData[key];
            console.log(`Processing ${name} with ${imeis.length} IMEIs in organization ${organization}`);
            
            // Check if this admin with the same name and organization already exists
            const existingAdmin = await MiddleAdmin.findOne({ name, organization });
            
            let adminEmail, adminPassword, adminStatus;
            let finalImeis;
            
            if (existingAdmin) {
                console.log(`Found existing admin: ${name} in ${organization}`);
                
                // Merge IMEIs and remove duplicates
                finalImeis = [...new Set([...existingAdmin.imeis, ...imeis])];
                
                // Update the admin record with new email if provided
                existingAdmin.imeis = finalImeis;
                if (email && existingAdmin.email !== email) {
                    console.log(`Updating email from ${existingAdmin.email} to ${email}`);
                    existingAdmin.email = email;
                }
                await existingAdmin.save();
                
                adminEmail = existingAdmin.email;
                adminPassword = existingAdmin.password; // Use actual password, not masked
                adminStatus = "Updated";
                
                console.log(`Updated ${name} with ${finalImeis.length} IMEIs`);
            } else {
                // Create new middle admin
                adminEmail = email || `clientlogin${counter}@gmail.com`; // Use provided email or generate one
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
        res.download(outputPath, 'middle_admins.xlsx', (err) => {
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
        const { page = 1, limit = 10, sortBy = 'createdAt', order = 'desc', search = '' } = req.query; // Added search parameter

        // Add detailed logging for search
        console.log('=== SEARCH DEBUG INFO ===');
        console.log('Query parameters received:', req.query);
        console.log('Search parameter:', search);
        console.log('Search type:', typeof search);
        console.log('Search length:', search ? search.length : 0);
        console.log('Search after trim:', search ? search.trim() : 'empty');
        console.log('Is search truthy?', !!search);
        console.log('Is search not empty after trim?', search && search.trim() !== '');
        console.log('========================');

        // Find the middle admin by email
        const middleAdmin = await MiddleAdmin.findOne({ email });
        if (!middleAdmin) {
            return res.status(404).json({ message: 'Middle admin not found' });
        }

        // Get the IMEIs assigned to the middle admin
        const assignedImeis = middleAdmin.imeis;
        console.log('Assigned IMEIs count:', assignedImeis.length);

        // Create position map to preserve IMEI order
        const imeiPositionMap = new Map();
        assignedImeis.forEach((imei, index) => {
            imeiPositionMap.set(imei, index);
            imeiPositionMap.set(imei.trim(), index); // Also store trimmed version
            imeiPositionMap.set(`${imei} `, index); // Also store with space
        });

        // Build search query - keep original query structure and add search if provided
        let query = { imei: { $in: assignedImeis } };
        console.log('Base query:', JSON.stringify(query));
        
        // Add search functionality to the MongoDB query if search term is provided
        if (search && search.trim() !== '') {
            console.log('APPLYING SEARCH FILTER');
            const searchRegex = new RegExp(search.trim(), 'i'); // Case-insensitive regex
            console.log('Search regex:', searchRegex);
            
            query = {
                ...query,
                $or: [
                    { name: searchRegex },
                    { email: searchRegex },
                    { imei: searchRegex }
                ]
            };
            console.log('Query with search applied:', JSON.stringify(query));
        } else {
            console.log('NO SEARCH FILTER APPLIED - using base query only');
        }

        // Fetch all users matching the criteria (for sorting by IMEI position)
        const allMatchingUsers = await User.find(query).select('-password');
        console.log('Total matching users from database:', allMatchingUsers.length);
        
        // Sort users based on their IMEI's position in the assignedImeis array
        allMatchingUsers.sort((a, b) => {
            const posA = imeiPositionMap.get(a.imei) ?? imeiPositionMap.get(a.imei.trim());
            const posB = imeiPositionMap.get(b.imei) ?? imeiPositionMap.get(b.imei.trim());
            
            // If position not found, put at end
            if (posA === undefined) return 1;
            if (posB === undefined) return -1;
            
            return posA - posB; // Sort by IMEI position
        });
        
        // Get the total count (for pagination info)
        const totalCount = allMatchingUsers.length;
        
        // Apply manual pagination after sorting
        const startIndex = (page - 1) * parseInt(limit);
        const endIndex = startIndex + parseInt(limit);
        const paginatedUsers = allMatchingUsers.slice(startIndex, endIndex);
        
        console.log('Users fetched for current page:', paginatedUsers.length);
        
        // Fetch the last reported data for each IMEI
        const authString = `${process.env.BODYTRACE_USER}:${process.env.BODYTRACE_PASS}`;
        const authToken = Buffer.from(authString).toString('base64');

        const usersWithLastReportedData = await Promise.all(
            paginatedUsers.map(async (user) => {
                try {
                    // Normalize IMEI by trimming spaces
                    const normalizedImei = String(user.imei).trim();
                    
                    const response = await axios.get(
                        `https://us.data.bodytrace.com/1/device/${normalizedImei}/datamessages`,
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

                    // Apply additional search filter to device data if search term is provided
                    if (search && search.trim() !== '' && lastReportedData) {
                        console.log(`Checking device data search for user ${user.email} with search term "${search}"`);
                        const searchTerm = search.toLowerCase();
                        const weightMatch = lastReportedData.values.weight && lastReportedData.values.weight.toString().includes(searchTerm);
                        const unitMatch = lastReportedData.values.unit && lastReportedData.values.unit.toString().toLowerCase().includes(searchTerm);
                        const tareMatch = lastReportedData.values.tare && lastReportedData.values.tare.toString().includes(searchTerm);
                        const deviceIdMatch = lastReportedData.deviceId && lastReportedData.deviceId.toString().includes(searchTerm);
                        const dateTimeMatch = new Date(lastReportedData.ts).toISOString().toLowerCase().includes(searchTerm);
                        
                        console.log(`Device data matches for ${user.email}:`, {
                            weight: weightMatch,
                            unit: unitMatch,
                            tare: tareMatch,
                            deviceId: deviceIdMatch,
                            dateTime: dateTimeMatch
                        });
                        
                        // If search term doesn't match device data, still include user (since they matched user data)
                        // This preserves the original behavior while adding device data search capability
                        const deviceDataMatches = weightMatch || unitMatch || tareMatch || deviceIdMatch || dateTimeMatch;
                        
                        // Log for debugging
                        if (!deviceDataMatches) {
                            console.log(`User ${user.email} matched user data but not device data for search: "${search}"`);
                        } else {
                            console.log(`User ${user.email} matched both user data AND device data for search: "${search}"`);
                        }
                    }

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

        console.log(`=== FINAL RESULTS ===`);
        console.log(`Search term: "${search}"`);
        console.log(`Users found: ${usersWithLastReportedData.length}`);
        console.log(`Total count: ${totalCount}`);
        console.log(`Current page: ${page}`);
        console.log(`Total pages: ${Math.ceil(totalCount / limit)}`);
        console.log(`====================`);

        // Respond with the paginated data including last reported data (keep original response structure)
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