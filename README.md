# Health Monitoring API

## Overview
The Health Monitoring API is a Node.js application designed to manage health data from various devices, including weight scales and blood pressure monitors. It provides an admin panel for user management and device data access, allowing users to log in and view their health metrics.

## Features
- Admin panel for user creation and management
- User authentication and registration
- Device data submission and retrieval based on IMEI numbers
- Email notifications for users
- Data storage in MongoDB

## Project Structure
```
health-monitoring-api
├── src
│   ├── config
│   ├── controllers
│   ├── middleware
│   ├── models
│   ├── routes
│   ├── services
│   ├── utils
│   └── app.js
├── .env
├── .gitignore
├── package.json
└── package-lock.json
```

## Installation
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/health-monitoring-api.git
   ```
2. Navigate to the project directory:
   ```
   cd health-monitoring-api
   ```
3. Install the dependencies:
   ```
   npm install
   ```
4. Create a `.env` file in the root directory and add your environment variables (e.g., MongoDB connection string).

## Usage
1. Start the server:
   ```
   npm start
   ```
2. Access the API at `http://localhost:3000`.

## API Endpoints
- **Admin Routes**
  - `POST /admin/create` - Create a new user
  - `GET /admin/users` - Retrieve all users

- **Auth Routes**
  - `POST /auth/login` - User login
  - `POST /auth/register` - User registration

- **Device Routes**
  - `POST /device/submit` - Submit device data
  - `GET /device/:imei` - Retrieve device data by IMEI

- **User Routes**
  - `GET /user/:id` - Retrieve user data

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.