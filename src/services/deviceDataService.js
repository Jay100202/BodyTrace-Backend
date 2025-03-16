const DeviceData = require('../models/DeviceData'); // Assuming a DeviceData model exists for storing device submissions

const submitWeightScaleData = async (data) => {
    try {
        const { imei, ts, batteryVoltage, signalStrength, values } = data;
        const weightScaleData = new DeviceData({
            imei,
            ts,
            batteryVoltage,
            signalStrength,
            type: 'weight_scale',
            values: {
                unit: values.unit,
                tare: values.tare,
                weight: values.weight
            }
        });
        await weightScaleData.save();
        return weightScaleData;
    } catch (error) {
        throw new Error('Error saving weight scale data: ' + error.message);
    }
};

const submitBloodPressureData = async (data) => {
    try {
        const { imei, ts, batteryVoltage, signalStrength, values } = data;
        const bloodPressureData = new DeviceData({
            imei,
            ts,
            batteryVoltage,
            signalStrength,
            type: 'blood_pressure',
            values: {
                systolic: values.systolic,
                diastolic: values.diastolic,
                pulse: values.pulse,
                unit: values.unit,
                irregular: values.irregular
            }
        });
        await bloodPressureData.save();
        return bloodPressureData;
    } catch (error) {
        throw new Error('Error saving blood pressure data: ' + error.message);
    }
};

const getDeviceDataByImei = async (imei) => {
    try {
        const deviceData = await DeviceData.find({ imei });
        return deviceData;
    } catch (error) {
        throw new Error('Error fetching device data: ' + error.message);
    }
};

module.exports = {
    submitWeightScaleData,
    submitBloodPressureData,
    getDeviceDataByImei
};