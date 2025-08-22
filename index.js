const axios = require('axios');
const configFile = require('./config.json'); // Ensure your config.json file has the necessary information

const SCAN_INTERVAL = 3 * 60 * 1000;

// Function to suspend a server
async function suspendServer(id) {
    try {
        const baseUrl = configFile.hydra.url;
        if (!baseUrl) {
            console.error('Base URL is missing in the config');
            return []; // Return empty array if the URL is missing
        }

        const url = `${baseUrl}/api/instances/suspend?key=${configFile.hydra.key}&id=${id}`;

        const response = await axios.get(url);
        
        if (response.status === 200) {
            console.log(`Server with ID: ${id} has been suspended successfully.`);
        } else {
            console.error(`Failed to suspend server with ID: ${id}. Status: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error suspending server with ID: ${id}.`, error.message);
    }
}

// Function to unsuspend a server
async function unsuspendServer(id) {
    try {
        const response = await axios.post(`http://${configFile.hydra.url}/api/instances/unsuspend/${id}?key=${configFile.hydra.key}`);
        if (response.status === 200) {
            console.log(`Server with ID: ${id} has been unsuspended successfully.`);
        } else {
            console.error(`Failed to unsuspend server with ID: ${id}. Status: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error unsuspending server with ID: ${id}.`, error.message);
    }
}

async function sendPublicAlert(serverId, reason) {
    const message = {
        embeds: [{
            title: "Suspicious activity detected by Sedar.",
            color: 0x5046e4,
            fields: [
                { name: "Container", value: serverId || "Unknown", inline: false },
                { name: "Reason", value: reason || "Unknown" }
            ],
            timestamp: new Date().toISOString(),
            footer: { text: 'Powered by Sedar 1' }
        }]
    };

    try {
        await axios.post(configFile.discord.webhook, message);
        console.log(`Sent public alert for container ${serverId}`);
    } catch (error) {
        console.error(`Error sending public alert for container ${serverId}:`, error);
    }
}

// Function to get all instances
async function getInstances() {
    try {
        const baseUrl = configFile.hydra.url;
        if (!baseUrl) {
            console.error('Base URL is missing in the config');
            return []; // Return empty array if the URL is missing
        }

        const url = `${baseUrl}/api/instances?key=${configFile.hydra.key}`;

        const response = await axios.get(url);
        
        if (response.status === 200) {
            if (response.data) {
                const activeInstances = response.data.filter(instance => !instance.suspended);
                return activeInstances;
            } else {
                console.error('No data received in response');
                return [];
            }
        } else {
            console.error(`Failed to retrieve instances. Status: ${response.status}`);
            return [];
        }
    } catch (error) {
        console.error('Error retrieving instances:', error.message);
        return [];
    }
}

// Function to get files from a specific instance
async function getInstanceFiles(id, path) {
    try {
        const baseUrl = configFile.node.url;
        if (!baseUrl) {
            console.error('Base URL is missing in the config');
            return [];
        }

        const url = `${baseUrl}/fs/${id}/files?path=${path}`;
        const response = await axios.get(url, {
            auth: {
                username: 'Skyport',
                password: configFile.node.key
            }
        });

        if (response.status === 200) {
            const files = response.data.files;
             
            if (Array.isArray(files)) {
                for (const file of files) {
                    console.log(`File: ${file.name} Extension: ${file.extension} Purpose: ${file.purpose}`);
                    if (file.isDirectory && !file.isEditable) {
                        await getInstanceFiles(id, file.name);
                    }
                    if (file.purpose === 'script') {
                        await suspendServer(id);
                        await sendPublicAlert(id, 'Detected a suspicious .sh File');
                    }
                     if (file.name === 'xmrig') {
                        await suspendServer(id);
                        await sendPublicAlert(id, 'Detected unauthorized activity: Mining Monero (XMR), which is not permitted.');
                    }
                    if (file.name === 'server.jar') {
                        let sizeInBytes;
                        if (file.size.includes('MB')) {
                            sizeInBytes = parseFloat(file.size) * 1024 * 1024;
                        } else if (file.size.includes('KB')) {
                            sizeInBytes = parseFloat(file.size) * 1024;
                        } else if (file.size.includes('B')) {
                            sizeInBytes = parseFloat(file.size);
                        } else {
                            console.error('Unknown size format:', file.size);
                            return;
                        }
                    
                        if (sizeInBytes < 18 * 1024 * 1024) {
                            await suspendServer(id);
                            await sendPublicAlert(id, 'Detected a suspicious server.jar file');
                        }
                    }
                    if (file.isEditable) {
                        continue;
                    }
                }
            } else {
                console.error('The "files" field is missing or not an array.');
            }
        } else {
            console.error(`Failed to retrieve files for instance with ID: ${id} at path: ${path}. Status: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error retrieving files for instance with ID: ${id} at path: ${path}.`, error.message);
    }
}

// Function to fetch all instances and process them
async function processAllInstances() {
    try {
        const instances = await getInstances();

        for (const instance of instances) {
            const id = instance.Id;
            console.log(`Processing instance with ID: ${id}`);
            await getInstanceFiles(id, '');
        }
    } catch (error) {
        console.error('Error processing instances:', error.message);
    }
}

// Main Execution
async function main() {
    console.log('Starting continuous container abuse detection...');
  
    while (true) {
        try {
            await processAllInstances();
            console.log(`Completed scan. Waiting ${SCAN_INTERVAL / 1000} seconds before next scan...`);
        } catch (error) {
            console.error('Error in scan cycle:', error);
        } finally {
            await new Promise(resolve => setTimeout(resolve, SCAN_INTERVAL));
        }
    }
}

main().catch(error => console.error('Error in anti-abuse script:', error));
