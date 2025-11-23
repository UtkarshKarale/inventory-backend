// inventory-backend/src/utils/db.js

export const getDb = (db) => {
    return {
        // Labs CRUD
        async getAllLabs() {
            const { results } = await db.prepare('SELECT * FROM labs').all();
            return results;
        },
        async getLabById(id) {
            const { results } = await db.prepare('SELECT * FROM labs WHERE lab_id = ?').bind(id).all();
            return results[0];
        },
        async createLab(lab_name, location, capacity) {
            const { success } = await db.prepare(
                'INSERT INTO labs (lab_name, location, capacity) VALUES (?, ?, ?)'
            )
            .bind(lab_name, location, capacity)
            .run();
            return success;
        },
        async updateLab(id, lab_name, location, capacity) {
            const { success } = await db.prepare(
                'UPDATE labs SET lab_name = ?, location = ?, capacity = ?, updated_at = CURRENT_TIMESTAMP WHERE lab_id = ?'
            )
            .bind(lab_name, location, capacity, id)
            .run();
            return success;
        },
        async deleteLab(id) {
            const { success } = await db.prepare('DELETE FROM labs WHERE lab_id = ?').bind(id).run();
            return success;
        },

        // Faculty CRUD
        async getAllFaculty() {
            const { results } = await db.prepare('SELECT * FROM faculty').all();
            return results;
        },
        async getFacultyById(id) {
            const { results } = await db.prepare('SELECT * FROM faculty WHERE faculty_id = ?').bind(id).all();
            return results[0];
        },
        async createFaculty(faculty_name, email, department, location) {
            const { success } = await db.prepare(
                'INSERT INTO faculty (faculty_name, email, department, location) VALUES (?, ?, ?, ?)'
            )
            .bind(faculty_name, email, department, location)
            .run();
            return success;
        },
        async updateFaculty(id, faculty_name, email, department, location) {
            const { success } = await db.prepare(
                'UPDATE faculty SET faculty_name = ?, email = ?, department = ?, location = ?, updated_at = CURRENT_TIMESTAMP WHERE faculty_id = ?'
            )
            .bind(faculty_name, email, department, location, id)
            .run();
            return success;
        },
        async deleteFaculty(id) {
            const { success } = await db.prepare('DELETE FROM faculty WHERE faculty_id = ?').bind(id).run();
            return success;
        },

        // Devices CRUD
        async getAllDevices({ lab_id = null, faculty_id = null, status = null } = {}) {
            let query = 'SELECT * FROM devices';
            const conditions = [];
            const bindings = [];
            
            if (lab_id !== null) { // Use !== null to distinguish from 0 or empty string if those were valid IDs
                conditions.push('lab_id = ?');
                bindings.push(lab_id);
            }
            if (faculty_id !== null) {
                conditions.push('faculty_id = ?');
                bindings.push(faculty_id);
            }
            if (status !== null) {
                conditions.push('status = ?');
                bindings.push(status);
            }

            if (conditions.length > 0) {
                query += ' WHERE ' + conditions.join(' AND ');
            }

            const { results } = await db.prepare(query).bind(...bindings).all();
            return results;
        },
        async getDeviceById(id) {
            const { results } = await db.prepare('SELECT * FROM devices WHERE device_id = ?').bind(id).all();
            return results[0];
        },
        async createDevice(deviceData) {
            const {
                lab_id, faculty_id, device_name, company, lab_location, device_type, status, price, ram, storage, cpu, gpu, last_maintenance_date, ink_levels, display_size
            } = deviceData;
            const { success } = await db.prepare(
                'INSERT INTO devices (lab_id, faculty_id, device_name, company, lab_location, device_type, status, price, ram, storage, cpu, gpu, last_maintenance_date, ink_levels, display_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            )
            .bind(lab_id, faculty_id, device_name, company, lab_location, device_type, status, price, ram, storage, cpu, gpu, last_maintenance_date, ink_levels, display_size)
            .run();
            return success;
        },
        async updateDevice(id, deviceData) {
            const {
                lab_id, faculty_id, device_name, company, lab_location, device_type, status, price, ram, storage, cpu, gpu, last_maintenance_date, ink_levels, display_size
            } = deviceData;
            const { success } = await db.prepare(
                'UPDATE devices SET lab_id = ?, faculty_id = ?, device_name = ?, company = ?, lab_location = ?, device_type = ?, status = ?, price = ?, ram = ?, storage = ?, cpu = ?, gpu = ?, last_maintenance_date = ?, ink_levels = ?, display_size = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(lab_id, faculty_id, device_name, company, lab_location, device_type, status, price, ram, storage, cpu, gpu, last_maintenance_date, ink_levels, display_size, id)
            .run();
            return success;
        },
        async deleteDevice(id) {
            const { success } = await db.prepare('DELETE FROM devices WHERE device_id = ?').bind(id).run();
            return success;
        },

        // Device Management
        async reassignDevice(device_id, new_faculty_id) {
            const { success } = await db.prepare(
                'UPDATE devices SET faculty_id = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(new_faculty_id, device_id)
            .run();
            return success;
        },
        async deselectDevice(device_id) {
            const { success } = await db.prepare(
                'UPDATE devices SET faculty_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(device_id)
            .run();
            return success;
        },
        async markDeviceAsDeadStock(device_id) {
            const { success } = await db.prepare(
                'UPDATE devices SET status = "dead_stock", updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(device_id)
            .run();
            return success;
        },

        // User Authentication
        async createUser(email, hashedPassword) {
            const { success, meta } = await db.prepare(
                'INSERT INTO users (email, password) VALUES (?, ?)'
            )
            .bind(email, hashedPassword)
            .run();
            if (success) {
                return { success: true, user_id: meta.last_row_id };
            }
            return { success: false };
        },
        async findUserByEmail(email) {
            const { results } = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email).all();
            return results[0];
        },
        async findUserById(user_id) {
            const { results } = await db.prepare('SELECT * FROM users WHERE user_id = ?').bind(user_id).all();
            return results[0];
        },
        async findUserByGoogleId(google_id) {
            const { results } = await db.prepare('SELECT * FROM users WHERE google_id = ?').bind(google_id).all();
            return results[0];
        },
        async updateGoogleId(user_id, google_id) {
            const { success } = await db.prepare(
                'UPDATE users SET google_id = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
            )
            .bind(google_id, user_id)
            .run();
            return success;
        },

        async getSystemStatusReportData() {
            const allDevices = await this.getAllDevices();

            const totalDevices = allDevices.length;
            const activeDevices = allDevices.filter(d => d.status === 'active').length;
            const deadStockDevices = allDevices.filter(d => d.status === 'dead_stock').length;

            const devicesByType = {};
            allDevices.forEach(device => {
                devicesByType[device.device_type] = (devicesByType[device.device_type] || 0) + 1;
            });

            const statusSummary = {
                'Total Devices': totalDevices,
                'Active Devices': activeDevices,
                'Dead Stock Devices': deadStockDevices,
            };

            const typeStatusData = [];
            for (const type in devicesByType) {
                const count = devicesByType[type];
                const active = allDevices.filter(d => d.device_type === type && d.status === 'active').length;
                const dead_stock = allDevices.filter(d => d.device_type === type && d.status === 'dead_stock').length;
                typeStatusData.push({
                    device_type: type,
                    total: count,
                    active: active,
                    dead_stock: dead_stock,
                });
            }

            return { statusSummary, typeStatusData };
        },
        
        async getDeadStockReportData() {
            const deadStockDevices = await this.getAllDevices({ status: 'dead_stock' }); // Assuming getAllDevices can filter by status
            return { deadStockDevices };
        },
        
        async getFacultyInventoryReportData() {
            const faculty = await this.getAllFaculty();
            const allDevices = await this.getAllDevices();

            // Group devices by faculty
            const facultyWithDevices = faculty.map(fac => {
                const devicesAssignedToFaculty = allDevices.filter(device => device.faculty_id === fac.faculty_id);
                return {
                    ...fac,
                    devices: devicesAssignedToFaculty,
                };
            });

            return { faculty: facultyWithDevices };
        },

        async getLabWiseReportData() {
            const labs = await this.getAllLabs();
            const allDevices = await this.getAllDevices();

            // Group devices by lab
            const labsWithDevices = labs.map(lab => {
                const devicesInLab = allDevices.filter(device => device.lab_id === lab.lab_id);
                return {
                    ...lab,
                    devices: devicesInLab,
                };
            });

            return { labs: labsWithDevices };
        },

        // Reports Data
        async getCompleteInventoryReportData() {
            const devices = await this.getAllDevices(); // Use existing getAllDevices
            const labs = await this.getAllLabs();     // Use existing getAllLabs
            const faculty = await this.getAllFaculty(); // Use existing getAllFaculty

            return { devices, labs, faculty };
        },

        // Helper to get or create HOD Cabin Lab ID
        async getOrCreateHodCabinLabId() {
            const HOD_CABIN_NAME = 'HOD Cabin';
            let { results } = await db.prepare('SELECT lab_id FROM labs WHERE lab_name = ?').bind(HOD_CABIN_NAME).all();
            if (results.length > 0) {
                return results[0].lab_id;
            } else {
                // Create the HOD Cabin lab if it doesn't exist
                const { success, meta } = await db.prepare(
                    'INSERT INTO labs (lab_name, location, capacity) VALUES (?, ?, ?)'
                )
                .bind(HOD_CABIN_NAME, 'HOD Cabin', 0) // Location and capacity can be default or null
                .run();
                if (success) {
                    return meta.last_row_id;
                } else {
                    throw new Error('Failed to create HOD Cabin lab');
                }
            }
        },

        // Dashboard Statistics
        async getDashboardStats() {
            try {
                const totalLabs = await db.prepare('SELECT COUNT(*) as count FROM labs').first();
                const totalFaculty = await db.prepare('SELECT COUNT(*) as count FROM faculty').first();
                const totalDevices = await db.prepare('SELECT COUNT(*) as count FROM devices').first();
                const totalComputers = await db.prepare("SELECT COUNT(*) as count FROM devices WHERE device_type IN ('laptop', 'desktop', 'server', 'monitor')").first();
                const totalPrinters = await db.prepare('SELECT COUNT(*) as count FROM devices WHERE device_type = "printer"').first();
                
                // New, more specific status counts for computers
                const totalComputersActive = await db.prepare("SELECT COUNT(*) as count FROM devices WHERE device_type IN ('laptop', 'desktop', 'server', 'monitor') AND status = 'active'").first();
                const totalComputersDeadStock = await db.prepare("SELECT COUNT(*) as count FROM devices WHERE device_type IN ('laptop', 'desktop', 'server', 'monitor') AND status = 'dead_stock'").first();

                return {
                    totalLabs: totalLabs.count,
                    totalFaculty: totalFaculty.count,
                    totalDevices: totalDevices.count,
                    totalComputers: totalComputers.count,
                    totalPrinters: totalPrinters.count,
                    // Pass the detailed computer status counts to the frontend
                    computersByStatus: {
                        active: totalComputersActive.count,
                        dead_stock: totalComputersDeadStock.count,
                    }
                };
            } catch (error) {
                console.error('Error in getDashboardStats:', error);
                throw error;
            }
        },
    };
};