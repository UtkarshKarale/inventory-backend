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
        async createFaculty(faculty_name, email, department) {
            const { success } = await db.prepare(
                'INSERT INTO faculty (faculty_name, email, department) VALUES (?, ?, ?)'
            )
            .bind(faculty_name, email, department)
            .run();
            return success;
        },
        async updateFaculty(id, faculty_name, email, department) {
            const { success } = await db.prepare(
                'UPDATE faculty SET faculty_name = ?, email = ?, department = ?, updated_at = CURRENT_TIMESTAMP WHERE faculty_id = ?'
            )
            .bind(faculty_name, email, department, id)
            .run();
            return success;
        },
        async deleteFaculty(id) {
            const { success } = await db.prepare('DELETE FROM faculty WHERE faculty_id = ?').bind(id).run();
            return success;
        },

        // Devices CRUD
        async getAllDevices() {
            const { results } = await db.prepare('SELECT * FROM devices').all();
            return results;
        },
        async getDeviceById(id) {
            const { results } = await db.prepare('SELECT * FROM devices WHERE device_id = ?').bind(id).all();
            return results[0];
        },
        async createDevice(device_name, device_type, configuration, status, lab_id, faculty_id) {
            const { success } = await db.prepare(
                'INSERT INTO devices (device_name, device_type, configuration, status, lab_id, faculty_id) VALUES (?, ?, ?, ?, ?, ?)'
            )
            .bind(device_name, device_type, configuration, status, lab_id, faculty_id)
            .run();
            return success;
        },
        async updateDevice(id, device_name, device_type, configuration, status, lab_id, faculty_id) {
            const { success } = await db.prepare(
                'UPDATE devices SET device_name = ?, device_type = ?, configuration = ?, status = ?, lab_id = ?, faculty_id = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(device_name, device_type, configuration, status, lab_id, faculty_id, id)
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

        // Dashboard Statistics
        async getDashboardStats() {
            const totalLabs = await db.prepare('SELECT COUNT(*) as count FROM labs').first();
            const totalFaculty = await db.prepare('SELECT COUNT(*) as count FROM faculty').first();
            const totalDevices = await db.prepare('SELECT COUNT(*) as count FROM devices').first();
            const totalComputers = await db.prepare('SELECT COUNT(*) as count FROM devices WHERE device_type = "computer"').first();
            const totalPrinters = await db.prepare('SELECT COUNT(*) as count FROM devices WHERE device_type = "printer"').first();
            const totalDeadStock = await db.prepare('SELECT COUNT(*) as count FROM devices WHERE status = "dead_stock"').first();

            return {
                totalLabs: totalLabs.count,
                totalFaculty: totalFaculty.count,
                totalDevices: totalDevices.count,
                totalComputers: totalComputers.count,
                totalPrinters: totalPrinters.count,
                totalDeadStock: totalDeadStock.count,
            };
        },
    };
};