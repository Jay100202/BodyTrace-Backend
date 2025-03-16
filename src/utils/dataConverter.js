const convertWeightToPounds = (grams) => {
    return Math.round((grams / 100 * 22046) / 100) / 10;
};

const convertPaToMmHg = (pascal) => {
    return Math.round(pascal * 0.0075006);
};

const convertDeviceData = (deviceData) => {
    if (deviceData.values) {
        if (deviceData.values.unit === 1) {
            deviceData.values.weightInPounds = convertWeightToPounds(deviceData.values.weight);
        }
        if (deviceData.values.systolic && deviceData.values.diastolic) {
            deviceData.values.systolicInMmHg = convertPaToMmHg(deviceData.values.systolic);
            deviceData.values.diastolicInMmHg = convertPaToMmHg(deviceData.values.diastolic);
        }
    }
    return deviceData;
};

module.exports = {
    convertWeightToPounds,
    convertPaToMmHg,
    convertDeviceData
};