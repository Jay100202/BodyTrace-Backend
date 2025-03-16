module.exports = {
    generateUserPayload: (name, email, password, imei) => {
        return {
            name,
            email,
            password,
            imei,
            createdAt: new Date(),
        };
    },

    formatDeviceData: (data) => {
        return {
            imei: data.imei,
            timestamp: new Date(data.ts),
            batteryVoltage: data.batteryVoltage / 1000, // Convert mV to V
            signalStrength: data.signalStrength,
            values: data.values,
        };
    },

    convertWeightToPounds: (grams) => {
        return Math.round((grams / 100 * 22046) / 100) / 10; // Convert grams to lbs
    },

    convertPressureToMmHg: (pa) => {
        return Math.round(pa * 0.0075006); // Convert Pa to mmHg
    },

    isValidEmail: (email) => {
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return regex.test(email);
    },

    isEmpty: (value) => {
        return value === null || value === undefined || value === '';
    },
};