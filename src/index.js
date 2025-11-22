import { Router } from './utils/customRouter';
import { getDb } from './utils/db'; // Import getDb
import bcrypt from 'bcryptjs'; // For password hashing
import { SignJWT, jwtVerify } from 'jose'; // For JWT

// Embed the schema directly as a string
// DB_SCHEMA is now broken down and executed step-by-step in /api/init-db
const DB_SCHEMA_PLACEHOLDER = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS labs (
  lab_id INTEGER PRIMARY KEY AUTOINCREMENT,
  lab_name TEXT NOT NULL UNIQUE,
  location TEXT,
  capacity INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS faculty (
  faculty_id INTEGER PRIMARY KEY AUTOINCREMENT,
  faculty_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  department TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
  device_id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_name TEXT NOT NULL,
  device_type TEXT NOT NULL,
  configuration TEXT,
  status TEXT DEFAULT 'active',
  lab_id INTEGER,
  faculty_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lab_id) REFERENCES labs (lab_id) ON DELETE SET NULL,
  FOREIGN KEY (faculty_id) REFERENCES faculty (faculty_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password TEXT, -- Hashed password for email/password login
  google_id TEXT UNIQUE, -- Google ID for Google Auth
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`;

const router = new Router();

// CORS handling (placed first to act as middleware)
router.all('*', (request) => {
    // Handle preflight OPTIONS requests
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': 'http://localhost:3000', // Allow your frontend origin
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Max-Age': '86400', // Cache preflight for 24 hours
            },
        });
    }
    return undefined; // Explicitly return undefined for non-OPTIONS requests to continue routing
});

// Helper function to generate JWT token
async function generateToken(user_id, env) {
    const secret = new TextEncoder().encode(env.JWT_SECRET);
    const alg = 'HS256';
    const jwt = await new SignJWT({ user_id })
        .setProtectedHeader({ alg })
        .setExpirationTime('2h') // Token expires in 2 hours
        .sign(secret);
    return jwt;
}

// Middleware to verify JWT token
async function authenticate(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response('Unauthorized', { status: 401 });
    }
    const token = authHeader.split(' ')[1];
    try {
        const secret = new TextEncoder().encode(env.JWT_SECRET);
        const { payload } = await jwtVerify(token, secret);
        request.user_id = payload.user_id; // Attach user_id to request
    } catch (error) {
        return new Response('Invalid or expired token', { status: 401 });
    }
}

// Add CORS headers to all responses (applied at the end of fetch)
const addCorsHeaders = (response) => {
    response.headers.set('Access-Control-Allow-Origin', 'http://localhost:3000');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    response.headers.set('Access-Control-Allow-Credentials', 'true'); // Important for sending cookies/auth headers
    return response;
};


router.get('/', () => {
	return new Response('Hello World from Inventory Backend!');
});

router.get('/api/init-db', async (request, env) => {
	try {
        // Execute PRAGMA first
        await env.DB.exec('PRAGMA foreign_keys = ON;');

        // Execute each CREATE TABLE statement separately
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS labs (
              lab_id INTEGER PRIMARY KEY AUTOINCREMENT,
              lab_name TEXT NOT NULL UNIQUE,
              location TEXT,
              capacity INTEGER,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS faculty (
              faculty_id INTEGER PRIMARY KEY AUTOINCREMENT,
              faculty_name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              department TEXT,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS devices (
              device_id INTEGER PRIMARY KEY AUTOINCREMENT,
              device_name TEXT NOT NULL,
              device_type TEXT NOT NULL,
              configuration TEXT,
              status TEXT DEFAULT 'active',
              lab_id INTEGER,
              faculty_id INTEGER,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (lab_id) REFERENCES labs (lab_id) ON DELETE SET NULL,
              FOREIGN KEY (faculty_id) REFERENCES faculty (faculty_id) ON DELETE SET NULL
            );
        `);
        await env.DB.exec(`
            CREATE TABLE IF NOT EXISTS users (
              user_id INTEGER PRIMARY KEY AUTOINCREMENT,
              email TEXT NOT NULL UNIQUE,
              password TEXT, -- Hashed password for email/password login
              google_id TEXT UNIQUE, -- Google ID for Google Auth
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        `);

		return new Response('Database schema initialized successfully!', { status: 200 });
	} catch (error) {
		return new Response(`Error initializing database: ${error.message}`, { status: 500 });
	}
});

// Authentication Routes
router.post('/api/auth/register', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { email, password } = await request.json();
        if (!email || !password) {
            return new Response('Email and password are required', { status: 400 });
        }

        const existingUser = await db.findUserByEmail(email);
        if (existingUser) {
            return new Response('User with this email already exists', { status: 409 });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Hash password with salt rounds
        const { success, user_id } = await db.createUser(email, hashedPassword); // Get user_id directly

        if (success) {
            const token = await generateToken(user_id, env); // Use the returned user_id
            return new Response(JSON.stringify({ message: 'User registered successfully', token }), {
                status: 201,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to register user', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error registering user: ${error.message}`, { status: 500 });
    }
});

router.post('/api/auth/login', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { email, password } = await request.json();
        if (!email || !password) {
            return new Response('Email and password are required', { status: 400 });
        }

        const user = await db.findUserByEmail(email);
        if (!user || !user.password) { // Check if user exists and has a password (not Google Auth only)
            return new Response('Invalid credentials', { status: 401 });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return new Response('Invalid credentials', { status: 401 });
        }

        const token = await generateToken(user.user_id, env);
        return new Response(JSON.stringify({ token }), {
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (error) {
        return new Response(`Error logging in: ${error.message}`, { status: 500 });
    }
    
});

// Google OAuth
router.get('/api/auth/google', async (request, env) => {
    const redirectUri = `${request.url.origin}/api/auth/google/callback`;
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${env.GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=email%20profile`;
    return Response.redirect(authUrl, 302);
});

router.get('/api/auth/google/callback', async (request, env) => {
    const db = getDb(env.DB);
    const code = request.url.searchParams.get('code');
    if (!code) {
        return new Response('Google OAuth failed: No code received', { status: 400 });
    }

    try {
        const redirectUri = `${request.url.origin}/api/auth/google/callback`;
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                code,
                client_id: env.GOOGLE_CLIENT_ID,
                client_secret: env.GOOGLE_CLIENT_SECRET,
                redirect_uri: redirectUri,
                grant_type: 'authorization_code',
            }).toString(),
        });
        const tokenData = await tokenResponse.json();

        if (tokenData.error) {
            return new Response(`Google OAuth token error: ${tokenData.error_description || tokenData.error}`, { status: 400 });
        }

        const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`,
            },
        });
        const userInfo = await userInfoResponse.json();

        if (userInfo.error) {
             return new Response(`Google User Info error: ${userInfo.error_description || userInfo.error}`, { status: 400 });
        }

        let user = await db.findUserByGoogleId(userInfo.sub);
        if (!user) {
            // Check if user exists with email, if so, link Google ID
            user = await db.findUserByEmail(userInfo.email);
            if (user) {
                await db.updateGoogleId(user.user_id, userInfo.sub);
            } else {
                // Create new user with Google ID
                const { success, meta } = await env.DB.prepare(
                    'INSERT INTO users (email, google_id) VALUES (?, ?)'
                )
                .bind(userInfo.email, userInfo.sub)
                .run();
                if (success) {
                    user = await db.findUserById(meta.last_row_id);
                } else {
                    throw new Error('Failed to create user with Google Auth');
                }
            }
        }

        const jwtToken = await generateToken(user.user_id, env);
        // Redirect to frontend with token (e.g., /dashboard?token=...)
        return Response.redirect(`${request.url.origin}/dashboard?token=${jwtToken}`, 302);

    } catch (error) {
        return new Response(`Google OAuth error: ${error.message}`, { status: 500 });
    }
});


// Dashboard Statistics (protected)
router.get('/api/dashboard', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const stats = await db.getDashboardStats();
        return new Response(JSON.stringify(stats), {
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (error) {
        return new Response(`Error fetching dashboard stats: ${error.message}`, { status: 500 });
    }
});

// Labs CRUD operations (protected)
router.get('/api/labs', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const labs = await db.getAllLabs();
        return new Response(JSON.stringify(labs), {
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (error) {
        return new Response(`Error fetching labs: ${error.message}`, { status: 500 });
    }
});

router.post('/api/labs', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { lab_name, location, capacity } = await request.json();
        if (!lab_name) {
            return new Response('Lab name is required', { status: 400 });
        }
        const success = await db.createLab(lab_name, location, capacity);
        if (success) {
            return new Response(JSON.stringify({ message: 'Lab created successfully' }), {
                status: 201,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to create lab', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error creating lab: ${error.message}`, { status: 500 });
    }
});

router.get('/api/labs/:id', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const lab = await db.getLabById(id);
        if (lab) {
            return new Response(JSON.stringify(lab), {
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Lab not found', { status: 404 });
        }
    } catch (error) {
        return new Response(`Error fetching lab: ${error.message}`, { status: 500 });
    }
});

router.put('/api/labs/:id', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const { lab_name, location, capacity } = await request.json();
        if (!lab_name) {
            return new Response('Lab name is required', { status: 400 });
        }
        const success = await db.updateLab(id, lab_name, location, capacity);
        if (success) {
            return new Response(JSON.stringify({ message: 'Lab updated successfully' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to update lab', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error updating lab: ${error.message}`, { status: 500 });
    }
});

router.delete('/api/labs/:id', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const success = await db.deleteLab(id);
        if (success) {
            return new Response(JSON.stringify({ message: 'Lab deleted successfully' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to delete lab', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error deleting lab: ${error.message}`, { status: 500 });
    }
});

// Faculty CRUD operations (protected)
router.get('/api/faculty', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const faculty = await db.getAllFaculty();
        return new Response(JSON.stringify(faculty), {
            headers: { 'Content-Type': 'application/json' },
        });
    } catch (error) {
        return new Response(`Error fetching faculty: ${error.message}`, { status: 500 });
    }
});

router.post('/api/faculty', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { faculty_name, email, department } = await request.json();
        if (!faculty_name || !email) {
            return new Response('Faculty name and email are required', { status: 400 });
        }
        const success = await db.createFaculty(faculty_name, email, department);
        if (success) {
            return new Response(JSON.stringify({ message: 'Faculty created successfully' }), {
                status: 201,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to create faculty', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error creating faculty: ${error.message}`, { status: 500 });
    }
});

router.get('/api/faculty/:id', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const faculty = await db.getFacultyById(id);
        if (faculty) {
            return new Response(JSON.stringify(faculty), {
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Faculty not found', { status: 404 });
        }
    } catch (error) {
        return new Response(`Error fetching faculty: ${error.message}`, { status: 500 });
    }
});

router.put('/api/faculty/:id', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const { faculty_name, email, department } = await request.json();
        if (!faculty_name || !email) {
            return new Response('Faculty name and email are required', { status: 400 });
        }
        const success = await db.updateFaculty(id, faculty_name, email, department);
        if (success) {
            return new Response(JSON.stringify({ message: 'Faculty updated successfully' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to update faculty', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error updating faculty: ${error.message}`, { status: 500 });
    }
});

router.delete('/api/faculty/:id', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const success = await db.deleteFaculty(id);
        if (success) {
            return new Response(JSON.stringify({ message: 'Faculty deleted successfully' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to delete faculty', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error deleting faculty: ${error.message}`, { status: 500 });
    }
});

// Devices CRUD operations (protected)
router.put('/api/devices/:id/reassign', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const { faculty_id } = await request.json();
        if (!faculty_id) {
            return new Response('Faculty ID is required for reassignment', { status: 400 });
        }
        const success = await db.reassignDevice(id, faculty_id);
        if (success) {
            return new Response(JSON.stringify({ message: 'Device reassigned successfully' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to reassign device', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error reassigning device: ${error.message}`, { status: 500 });
    }
});

router.put('/api/devices/:id/deselect', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const success = await db.deselectDevice(id);
        if (success) {
            return new Response(JSON.stringify({ message: 'Device deselected successfully' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to deselect device', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error deselecting device: ${error.message}`, { status: 500 });
    }
});

router.put('/api/devices/:id/deadstock', async (request, env) => {
    const db = getDb(env.DB);
    try {
        const { id } = request.params;
        const success = await db.markDeviceAsDeadStock(id);
        if (success) {
            return new Response(JSON.stringify({ message: 'Device marked as dead stock successfully' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        } else {
            return new Response('Failed to mark device as dead stock', { status: 500 });
        }
    } catch (error) {
        return new Response(`Error marking device as dead stock: ${error.message}`, { status: 500 });
    }
});

// Final 404 handler (placed last)
router.all('*', () => new Response('Not Found.', { status: 404 }));

export default {
	async fetch(request, env, ctx) {
        console.log('--- fetch handler start ---');
		const response = await router.handle(request, env, ctx);
        console.log('Response from router.handle:', response);
        if (response instanceof Response) {
            return addCorsHeaders(response);
        }
        // If router.handle somehow returns something that is not a Response object,
        // return a 500 Internal Server Error.
        return new Response('Internal Server Error: Router did not return a valid Response.', { status: 500 });
	},
};