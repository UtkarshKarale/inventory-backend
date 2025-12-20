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
            const normalizedEmail = email.trim().toLowerCase();
            const { success } = await db.prepare(
                'INSERT INTO faculty (faculty_name, email, department, location) VALUES (?, ?, ?, ?)'
            )
            .bind(faculty_name, normalizedEmail, department, location)
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
        async getAllDevices({ lab_id = null, faculty_id = null, status = null, device_type = null } = {}) {
            let query = "SELECT device_id, lab_id, faculty_id, device_name, company, lab_location, device_type, status, ram, storage, cpu, ip_generation, last_maintenance_date, ink_levels, display_size, invoice_number, remark, updated_at, CASE WHEN invoice_pdf IS NOT NULL AND invoice_pdf != '' THEN 1 ELSE 0 END as has_invoice_pdf FROM devices";
            const conditions = [];
            const bindings = [];
            
            if (lab_id !== null) {
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
            if (device_type !== null) {
                if (Array.isArray(device_type)) {
                    conditions.push(`TRIM(device_type) IN (${device_type.map(() => '?').join(', ')})`);
                    bindings.push(...device_type);
                } else {
                    conditions.push('TRIM(device_type) = ?');
                    bindings.push(device_type);
                }
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
                lab_id = null,
                faculty_id = null,
                device_name,
                company = null,
                lab_location = null,
                device_type,
                status,
                ram = null,
                storage = null,
                cpu = null,
                gpu = null,
                last_maintenance_date = null,
                ink_levels = null,
                display_size = null,
                invoice_number = null,
                invoice_pdf = null,
                remark = null,
                ip_generation = null
            } = deviceData;
            const { success } = await db.prepare(
                'INSERT INTO devices (lab_id, faculty_id, device_name, company, lab_location, device_type, status, ram, storage, cpu, ip_generation, last_maintenance_date, ink_levels, display_size, invoice_number, invoice_pdf, remark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            )
            .bind(lab_id, faculty_id, device_name, company, lab_location, device_type, status, ram, storage, cpu, ip_generation, last_maintenance_date, ink_levels, display_size, invoice_number, invoice_pdf, remark)
            .run();
            return success;
        },
        async updateDevice(id, deviceData) {
            let {
                lab_id, faculty_id, device_name, company, lab_location, device_type, status, ram, storage, cpu, ip_generation, last_maintenance_date, ink_levels, display_size
            } = deviceData;

            if (faculty_id) {
                lab_id = null;
            } else if (lab_id) {
                faculty_id = null;
            }

            const { success } = await db.prepare(
                'UPDATE devices SET lab_id = ?, faculty_id = ?, device_name = ?, company = ?, lab_location = ?, device_type = ?, status = ?, ram = ?, storage = ?, cpu = ?, ip_generation = ?, last_maintenance_date = ?, ink_levels = ?, display_size = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(lab_id, faculty_id, device_name, company, lab_location, device_type, status, ram, storage, cpu, ip_generation, last_maintenance_date, ink_levels, display_size, id)
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
                'UPDATE devices SET faculty_id = ?, lab_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(new_faculty_id, device_id)
            .run();
            return success;
        },
        async reassignDeviceToLab(device_id, new_lab_id) {
            const { success } = await db.prepare(
                'UPDATE devices SET lab_id = ?, faculty_id = NULL, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(new_lab_id, device_id)
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
        async markDeviceAsDeadStock(device_id, remark) {
            const { success } = await db.prepare(
                'UPDATE devices SET status = "dead_stock", remark = ?, updated_at = CURRENT_TIMESTAMP WHERE device_id = ?'
            )
            .bind(remark, device_id)
            .run();
            return success;
        },

        async markPartsAsDeadStock(originalDeviceId, parts, remark) {
            const { results } = await db.prepare('SELECT * FROM devices WHERE device_id = ?').bind(originalDeviceId).all();
            const originalDevice = results[0];

            if (!originalDevice) {
                throw new Error('Original device not found');
            }

            const statements = [];

            for (const part of parts) {
                const newDeviceName = `${part.charAt(0).toUpperCase() + part.slice(1)} from ${originalDevice.device_name}`;
                
                // Create a new device for the dead stock part
                statements.push(
                    db.prepare(
                        'INSERT INTO devices (device_name, device_type, status, remark, company, invoice_number) VALUES (?, ?, ?, ?, ?, ?)'
                    )
                    .bind(
                        newDeviceName,
                        part, // 'mouse', 'keyboard', etc.
                        'dead_stock',
                        remark,
                        originalDevice.company,
                        originalDevice.invoice_number
                    )
                );
            }
            
            // Update the original device's remark
            const newRemark = `Parts moved to dead stock: ${parts.join(', ')}. ${remark}`;
            const updatedRemark = originalDevice.remark ? `${originalDevice.remark}\n${newRemark}` : newRemark;

            statements.push(
                db.prepare('UPDATE devices SET remark = ? WHERE device_id = ?')
                .bind(updatedRemark, originalDeviceId)
            );

            const results_batch = await db.batch(statements);
            
            // Check if all statements in the batch were successful
            return results_batch.every(result => result.success);
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
            const activeDevices = await this.getAllDevices({ status: 'active' }); // Fetch only active devices

            // Group devices by faculty
            const facultyWithDevices = faculty.map(fac => {
                const devicesAssignedToFaculty = activeDevices.filter(device => device.faculty_id === fac.faculty_id);
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
                const [
                    totalFaculty,
                    totalDevices,
                    totalComputers,
                    totalPrinters,
                    totalDigitalBoards,
                    totalPointers,
                    totalProjectors,
                    totalCPUs,
                    totalMice,
                    totalKeyboards,
                    totalComputersActive,
                    totalComputersDeadStock,
                    devicesByLab,
                ] = await Promise.all([
                    db.prepare('SELECT COUNT(*) as count FROM faculty').first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) IN ('laptop', 'desktop', 'server', 'monitor') AND status = 'active'").first(),
                    db.prepare('SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) = "printer" AND status = \'active\'').first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) = 'digital_board' AND status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) = 'pointer' AND status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) = 'projector' AND status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) = 'cpu' AND status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) = 'mouse' AND status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE TRIM(device_type) = 'keyboard' AND status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE device_type IN ('laptop', 'desktop', 'server', 'monitor') AND status = 'active'").first(),
                    db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'dead_stock'").first(),
                    db.prepare(`
                        SELECT
                            l.lab_id,
                            l.lab_name as lab,
                            COUNT(d.device_id) as count
                        FROM labs l
                        LEFT JOIN devices d ON l.lab_id = d.lab_id AND d.status = 'active'
                        GROUP BY l.lab_id, l.lab_name
                        ORDER BY l.lab_name
                    `).all(),
                ]);

                return {
                    totalFaculty: totalFaculty.count,
                    totalDevices: totalDevices.count,
                    totalComputers: totalComputers.count,
                    totalPrinters: totalPrinters.count,
                    totalDigitalBoards: totalDigitalBoards.count,
                    totalPointers: totalPointers.count,
                    totalProjectors: totalProjectors.count,
                    totalCPUs: totalCPUs.count,
                    totalMice: totalMice.count,
                    totalKeyboards: totalKeyboards.count,
                    computersByStatus: {
                        active: totalComputersActive.count,
                        dead_stock: totalComputersDeadStock.count,
                    },
                    devicesByLab: devicesByLab.results,
                };
            } catch (error) {
                throw error;
            }
        },
    };
};
