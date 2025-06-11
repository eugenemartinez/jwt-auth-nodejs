import http from 'http';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { dbPromise } from './db';
import { 
    jwtSecret, 
    authenticateJWT, 
    requireEmailVerified, 
    verify2FACode,
    VerifiedRequest,
    rateLimitMiddleware
} from './middleware';
import { 
    parseJsonBody, 
    sendJsonResponse , 
    handleError, 
    validatePasswordStrength, 
    sendVerificationEmail, 
    sendPasswordResetEmail, 
    send2FACodeEmail,
    sanitizeContent,
    generateRefreshToken,
    generate2FACode,
    hashToken,
} from './utils';

dotenv.config();

const PORT = process.env.PORT || 3000;

const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS
    ? process.env.CORS_ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
    : ['*'];

const server = http.createServer(async (req, res) => {

    // Set CORS headers
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    } else if (allowedOrigins.includes('*')) {
        res.setHeader('Access-Control-Allow-Origin', '*');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-refresh-token, x-page, x-limit');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // Rate limiting middleware
    if (!(await rateLimitMiddleware(req, res))) return;

    // Initialize db
    const db = await dbPromise;
    if (!db) {
        handleError(res, 500, 'Database connection failed.');
        return;
    }

    // Root endpoint
    if (req.method === 'GET' && req.url === '/') {
        sendJsonResponse(res, 200, { message: 'Welcome to the API!' });
        return;
    }

    // START AUTHENTICATION ENDPOINTS

    // Register endpoint
    if (req.method === 'POST' && req.url === '/auth/register') {
        try {
            const data = await parseJsonBody(req);
            const { username, email, password } = data;
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            
            // Sanitize inputs
            const sanitizedUsername = sanitizeContent(username);
            const sanitizedEmail = sanitizeContent(email);

            // Validate input
            if (!sanitizedUsername || !sanitizedEmail || !password) {
                sendJsonResponse(res, 400, { error: 'Username, email, and password are required.' });
                return;
            }

            // Check if username is alphanumeric and underscores only
            if (!/^[a-zA-Z0-9_]+$/.test(sanitizedUsername)) {
                sendJsonResponse(res, 400, { error: 'Username can only contain alphanumeric characters and underscores.' });
                return;
            }

            // check if email is alphanumeric and underscores only
            if (!/^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/.test(sanitizedEmail)) {
                sendJsonResponse(res, 400, { error: 'Email can only contain alphanumeric characters, underscores, and must be in a valid format.' });
                return;
            }

            // check if username has a length of 3-20 characters
            if (sanitizedUsername.length < 3 || sanitizedUsername.length > 20) {
                sendJsonResponse(res, 400, { error: 'Username must be between 3 and 20 characters long.' });
                return;
            }

            // Check if email has a length of 5-50 characters
            if (sanitizedEmail.length < 5 || sanitizedEmail.length > 50) {
                sendJsonResponse(res, 400, { error: 'Email must be between 5 and 50 characters long.' });
                return;
            }

            // Check if password has a length of 8-100 characters
            if (password.length < 8 || password.length > 100) {
                sendJsonResponse(res, 400, { error: 'Password must be between 8 and 100 characters long.' });
                return;
            }

            // Check if username, email, and password are strings
            if (typeof sanitizedUsername !== 'string' || typeof sanitizedEmail !== 'string' || typeof password !== 'string') {
                sendJsonResponse(res, 400, { error: 'Username, email, and password must be strings.' });
                return;
            }

            // Validate email format
            if (!emailRegex.test(sanitizedEmail)) {
                sendJsonResponse(res, 400, { error: 'Invalid email format.' });
                return;
            }

            // UNCOMMENT AFTER DEVELOPMENT
            // // Validate password strength
            // const passwordError = validatePasswordStrength(password);
            // if (passwordError) {
            //     sendJsonResponse(res, 400, { error: passwordError });
            //     return;
            // }

            // Insert user into the database
            const hashedPassword = await bcrypt.hash(password, 10);
            const avatar = sanitizedUsername;

            // generate email verification token and expiration
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

            await db.run(
                `INSERT INTO users (username, email, avatar, password_hash, verification_token, verification_expires) VALUES (?, ?, ?, ?, ?, ?)`,
                [sanitizedUsername, sanitizedEmail, avatar, hashedPassword, verificationToken, verificationExpires]
            );

            // Send verification email
            await sendVerificationEmail({
                email: sanitizedEmail,
                username: sanitizedUsername,
                verificationToken
            });

            sendJsonResponse(res, 201, { message: 'User registered successfully. Please check your email to verify your account' });

        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else if (err instanceof Error && err.message.includes('UNIQUE constraint failed')) {
                handleError(res, 409, 'Username or email already exists.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // Verification email endpoint
    if (req.method === 'POST' && req.url === '/auth/verify-email') {
        try {
            const data = await parseJsonBody(req);
            const { email, verificationToken } = data;

            // Validate input
            if (!email || !verificationToken) {
                sendJsonResponse(res, 400, { error: 'Email and verification token are required.' });
                return;
            }

            // Check if email is a valid format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                sendJsonResponse(res, 400, { error: 'Invalid email format.' });
                return;
            }

            // Fetch user by email
            const user = await db.get(
                `SELECT * FROM users WHERE email = ?`,
                [email]
            );

            if (!user) {
                sendJsonResponse(res, 404, { error: 'User not found.' });
                return;
            }

            // Check if the verification token matches
            if (user.verification_token !== verificationToken) {
                sendJsonResponse(res, 400, { error: 'Invalid verification token.' });
                return;
            }

            // Update user to mark email as verified
            await db.run(
                `UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?`,
                [user.id]
            );

            sendJsonResponse(res, 200, { message: 'Email verified successfully.' });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // resend verification email endpoint
    if (req.method === 'POST' && req.url === '/auth/resend-verification') {
        try {
            const data = await parseJsonBody(req);
            const { email } = data;

            // Validate input
            if (!email) {
                sendJsonResponse(res, 400, { error: 'Email is required.' });
                return;
            }

            // Check if email is a valid format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                sendJsonResponse(res, 400, { error: 'Invalid email format.' });
                return;
            }

            // Fetch user by email
            const user = await db.get(
                `SELECT * FROM users WHERE email = ?`,
                [email]
            );

            if (!user) {
                sendJsonResponse(res, 404, { error: 'User not found.' });
                return;
            }

            // Check if email is already verified
            if (user.email_verified) {
                sendJsonResponse(res, 400, { error: 'Email is already verified.' });
                return;
            }

            // Generate new verification token and expiration
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

            // Update user with new verification token
            await db.run(
                `UPDATE users SET verification_token = ?, verification_expires = ? WHERE id = ?`,
                [verificationToken, verificationExpires, user.id]
            );

            // Send verification email
            await sendVerificationEmail({
                email,
                username: user.username,
                verificationToken
            });

            sendJsonResponse(res, 200, { message: 'Verification email resent successfully.' });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // password reset request endpoint
    if (req.method === 'POST' && req.url === '/auth/request-password-reset') {
        try {
            const data = await parseJsonBody(req);
            const { email } = data;

            // Validate input
            if (!email) {
                sendJsonResponse(res, 400, { error: 'Email is required.' });
                return;
            }

            // Check if email is a valid format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                sendJsonResponse(res, 400, { error: 'Invalid email format.' });
                return;
            }

            // Fetch user by email
            const user = await db.get(
                `SELECT * FROM users WHERE email = ?`,
                [email]
            );

            if (!user) {
                sendJsonResponse(res, 404, { error: 'User not found.' });
                return;
            }

            // Generate password reset token and expiration
            const resetToken = crypto.randomBytes(32).toString('hex');
            const resetExpires = new Date(Date.now() + 1 * 60 * 60 * 1000).toISOString(); // 1 hour

            // Update user with reset token and expiration
            await db.run(
                `UPDATE users SET verification_token = ?, verification_expires = ? WHERE id = ?`,
                [resetToken, resetExpires, user.id]
            );

            const resetUrl = process.env.APP_URL + `/auth/reset-password?token=${resetToken}`;

            // Send password reset email
            await sendPasswordResetEmail({
                email,
                username: user.username,
                resetUrl
            });

            sendJsonResponse(res, 200, { message: 'Password reset email sent successfully.' });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // password reset endpoint
    if (req.method === 'POST' && req.url === '/auth/reset-password') {
        try {
            const data = await parseJsonBody(req);
            const { token, newPassword } = data;

            // Validate input
            if (!token || !newPassword) {
                sendJsonResponse(res, 400, { error: 'Token and new password are required.' });
                return;
            }

            // Check if newPassword is a string
            if (typeof newPassword !== 'string') {
                sendJsonResponse(res, 400, { error: 'New password must be a string.' });
                return;
            }

            // UNCOMMENT AFTER DEVELOPMENT
            // // Validate password strength
            // const passwordError = validatePasswordStrength(newPassword);
            // if (passwordError) {
            //     sendJsonResponse(res, 400, { error: passwordError });
            //     return;
            // }

            // Fetch user by reset token
            const user = await db.get(
                `SELECT * FROM users WHERE verification_token = ? AND verification_expires > CURRENT_TIMESTAMP`,
                [token]
            );

            if (!user) {
                sendJsonResponse(res, 404, { error: 'Invalid or expired reset token.' });
                return;
            }

            // Hash new password and update in the database
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            await db.run(
                `UPDATE users SET password_hash = ?, verification_token = NULL, verification_expires = NULL WHERE id = ?`,
                [hashedNewPassword, user.id]
            );

            sendJsonResponse(res, 200, { message: 'Password reset successfully.' });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // Login endpoint
    if (req.method === 'POST' && req.url === '/auth/login') {
        try {
            const data = await parseJsonBody(req);
            const { account, password } = data;

            // Validate input
            if (!account || !password) {
                sendJsonResponse(res, 400, { error: 'Account (username or email) and password are required.' });
                return;
            }

            // Check if username and password are strings
            if (typeof account !== 'string' || typeof password !== 'string') {
                sendJsonResponse(res, 400, { error: 'Username and password must be strings.' });
                return;
            }

            // Fetch user from the database
            const user = await db.get(
                `SELECT * FROM users WHERE username = ? OR email = ?`,
                [account, account]
            );
            if (!user) {
                sendJsonResponse(res, 401, { error: 'Invalid username or password.' });
                return;
            }

            // Verify password
            const isPasswordValid = await bcrypt.compare(password, user.password_hash);
            if (!isPasswordValid) {
                sendJsonResponse(res, 401, { error: 'Invalid username or password.' });
                return;
            }

            // get user id
            const userId = user.id;

            // generate 2fa code
            const twoFACode = await generate2FACode(userId);

            // send 2fa code to user's email
            await send2FACodeEmail({
                email: user.email,
                username: user.username,
                code: twoFACode
            });

            sendJsonResponse(res, 200, { message: 'Login successful. Please enter the 2FA code sent to your email.', requires2FA: true });

        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // 2FA Login endpoint
    if (req.method === 'POST' && req.url === '/auth/login-2fa') {
        try {
            const data = await parseJsonBody(req);
            const { account, password, code } = data;

            // Validate input
            if (!account || !password || !code) {
                sendJsonResponse(res, 400, { error: 'Account (username or email), password, and 2FA code are required.' });
                return;
            }

            // Check if username and password are strings
            if (typeof account !== 'string' || typeof password !== 'string' || typeof code !== 'string') {
                sendJsonResponse(res, 400, { error: 'Username, password, and 2FA code must be strings.' });
                return;
            }

            // Fetch user from the database
            const user = await db.get(
                `SELECT * FROM users WHERE username = ? OR email = ?`,
                [account, account]
            );
            if (!user) {
                sendJsonResponse(res, 401, { error: 'Invalid username or password.' });
                return;
            }

            // Verify password
            const isPasswordValid = await bcrypt.compare(password, user.password_hash);
            if (!isPasswordValid) {
                sendJsonResponse(res, 401, { error: 'Invalid username or password.' });
                return;
            }

            // Verify 2FA code
            const isCodeValid = await verify2FACode(user.id, code, res);
            if (!isCodeValid) return;

            // Generate JWT
            const token = jwt.sign(
                { id: user.id, username: user.username, email_verified: user.email_verified },
                jwtSecret,
                { expiresIn: '1d' }
            );

            // Generate refresh token
            const refreshToken = generateRefreshToken();
            const hashedRefreshToken = hashToken(refreshToken);
            const expirationDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
            const userAgent = req.headers['user-agent'] || '';

            // capture ip address
            const ipAddress = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress || '';

            // Store refresh token in the database
            await db.run(
                `INSERT INTO sessions (user_id, refresh_token, user_agent, expires_at, ip_address) VALUES (?, ?, ?, ?, ?)`,
                [user.id, hashedRefreshToken, userAgent, expirationDate, ipAddress]
            );
            sendJsonResponse(res, 200, { message: 'Login successful.', token, refreshToken });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // Refresh Token endpoint
    if (req.method === 'POST' && req.url === '/auth/refresh') {
        try {
            const data = await parseJsonBody(req);
            const { refreshToken } = data;

            // Validate input
            if (!refreshToken) {
                sendJsonResponse(res, 400, { error: 'Refresh token is required.' });
                return;
            }

            // Check if refreshToken is a string
            if (typeof refreshToken !== 'string') {
                sendJsonResponse(res, 400, { error: 'Refresh token must be a string.' });
                return;
            }

            // Hash the refresh token for comparison
            const hashedRefreshToken = hashToken(refreshToken);

            // check if the refresh token exists in the database
            const session = await db.get(
                'SELECT * FROM sessions WHERE refresh_token = ? AND expires_at > ?',
                [hashedRefreshToken, new Date().toISOString()]
            );
            if (!session) {
                sendJsonResponse(res, 401, { error: 'Invalid or expired refresh token.' });
                return;
            }

            // check if user exists
            if (!session.user_id) {
                sendJsonResponse(res, 401, { error: 'Invalid session.' });
                return;
            }

            // Generate new JWT
            const user = await db.get(
                `SELECT id, username, email_verified FROM users WHERE id = ?`,
                [session.user_id]
            );

            if (!user) {
                sendJsonResponse(res, 404, { error: 'User not found.' });
                return;
            }

            // generate new refresh token and expiration
            const newRefreshToken = generateRefreshToken();
            const newRefreshTokenHash = hashToken(newRefreshToken);
            const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

            // store refresh token in the database
            await db.run(
                `UPDATE sessions SET refresh_token = ?, expires_at = ? WHERE id = ?`,
                [newRefreshTokenHash, newExpiresAt, session.id]
            );

            // Generate new JWT
            const newToken = jwt.sign(
                { id: user.id, username: user.username, email_verified: user.email_verified },
                jwtSecret,
                { expiresIn: '1d' }
            );

            sendJsonResponse(res, 200, { message: 'Token refreshed successfully.', token: newToken, refreshToken: newRefreshToken });

        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // Logout endpoint and delete current session
    if (req.method === 'POST' && req.url === '/auth/logout') {
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            // Get refresh token from header or body
            const refreshToken = req.headers['x-refresh-token'] || (await parseJsonBody(req)).refreshToken;
            if (!refreshToken || typeof refreshToken !== 'string') {
                sendJsonResponse(res, 400, { error: 'Refresh token is required.' });
                return;
            }

            const hashedRefreshToken = hashToken(refreshToken);

            // Delete session by user and refresh token
            const result = await db.run(
                `DELETE FROM sessions WHERE user_id = ? AND refresh_token = ?`,
                [user.id, hashedRefreshToken]
            );

            if (result.changes === 0) {
                sendJsonResponse(res, 404, { error: 'Session not found.' });
                return;
            }

            sendJsonResponse(res, 200, { message: 'Logged out successfully.' });
        } catch (err: unknown) {
            console.error('Error logging out:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // logout all sessions endpoint
    if (req.method === 'POST' && req.url === '/auth/logout-all') {
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            // Delete all sessions for the user
            await db.run(
                `DELETE FROM sessions WHERE user_id = ?`,
                [user.id]
            );

            sendJsonResponse(res, 200, { message: 'Logged out from all sessions successfully.' });
        } catch (err: unknown) {
            console.error('Error logging out from all sessions:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // END AUTHENTICATION ENDPOINTS

    // START SESSION MANAGEMENT ENDPOINTS

    // GET Sessions endpoint with pagination
    if (req.method === 'GET' && req.url === '/sessions') {
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            // Fetch sessions for the user with pagination
            const page = parseInt((req.headers['x-page'] as string) || '1', 10);
            const limit = parseInt((req.headers['x-limit'] as string) || '10', 10);
            const offset = (page - 1) * limit;

            const sessions = await db.all(
                `SELECT id, user_agent, created_at, expires_at, ip_address FROM sessions WHERE user_id = ? LIMIT ? OFFSET ?`,
                [user.id, limit, offset]
            );

            // display current session and match by current session ID
            const refreshToken = req.headers['x-refresh-token'] || (await parseJsonBody(req)).refreshToken;
            let currentSession = null;
            if (refreshToken && typeof refreshToken === 'string') {
                const hashedRefreshToken = hashToken(refreshToken);
                currentSession = await db.get(
                    `SELECT id, user_agent, created_at, expires_at, ip_address FROM sessions WHERE user_id = ? AND refresh_token = ?`,
                    [user.id, hashedRefreshToken]
                );
            }

            // total sessions count
            const totalSessions = await db.get(
                `SELECT COUNT(*) as count FROM sessions WHERE user_id = ?`,
                [user.id]
            );

            sendJsonResponse(res, 200, { sessions, currentSession, page, limit, total: totalSessions.count });
        } catch (err: unknown) {
            console.error('Error fetching sessions:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // Delete Session endpoint
    if (req.method === 'DELETE' && /^\/sessions\/\d+$/.test(req.url || '')) {
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            const sessionId = req.url?.split('/').pop();
            if (!sessionId) {
                sendJsonResponse(res, 400, { error: 'Session ID is required.' });
                return;
            }

            // Delete session from the database
            const result = await db.run(
                `DELETE FROM sessions WHERE id = ? AND user_id = ?`,
                [sessionId, user.id]
            );

            if (result.changes === 0) {
                sendJsonResponse(res, 404, { error: 'Session not found.' });
                return;
            }

            sendJsonResponse(res, 200, { message: 'Session deleted successfully.' });
        } catch (err: unknown) {
            console.error('Error deleting session:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // END SESSION MANAGEMENT ENDPOINTS

    // START USER MANAGEMENT ENDPOINTS

    // GET Profile endpoint
    if (req.method === 'GET' && req.url === '/profile') {
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            // Fetch user profile from the database
            const profile = await db.get(
                `SELECT id, username, email, bio, avatar FROM users WHERE id = ?`,
                [user.id]
            );

            if (!profile) {
                sendJsonResponse(res, 404, { error: 'Profile not found.' });
                return;
            }

            sendJsonResponse(res, 200, profile);
        } catch (err: unknown) {
            console.error('Error fetching profile:', err);
            handleError(res, 500, 'Internal server error.', err);
            return
        }
        return;
    }

    // Update Profile endpoint
    if (req.method === 'PUT' && req.url === '/profile') {
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            const data = await parseJsonBody(req);
            const { bio, avatar } = data;

            // sanitize inputs
            // Type check before sanitizing
            const sanitizedBio = typeof bio === 'string' ? sanitizeContent(bio) : undefined;
            const sanitizedAvatar = typeof avatar === 'string' ? sanitizeContent(avatar) : undefined;

            // Validate input
            if (sanitizedBio !== undefined && typeof sanitizedBio !== 'string') {
                sendJsonResponse(res, 400, { error: 'Bio must be a string.' });
                return;
            }
            if (sanitizedAvatar !== undefined && typeof sanitizedAvatar !== 'string') {
                sendJsonResponse(res, 400, { error: 'Avatar must be a string.' });
                return;
            }

            // Check if bio and avatar are within length limits
            if (sanitizedBio && (sanitizedBio.length > 500)) {
                sendJsonResponse(res, 400, { error: 'Bio must be between 0 and 500 characters long.' });
                return;
            }

            if (sanitizedAvatar && (sanitizedAvatar.length > 100)) {
                sendJsonResponse(res, 400, { error: 'Avatar must be between 0 and 100 characters long.' });
                return;
            }

            // Build dynamic SQL
            const fields = [];
            const values = [];
            if (sanitizedBio !== undefined) {
                fields.push('bio = ?');
                values.push(sanitizedBio);
            }
            if (sanitizedAvatar !== undefined) {
                const avatar = sanitizedAvatar;
                fields.push('avatar = ?');
                values.push(avatar);
            }
            if (fields.length === 0) {
                sendJsonResponse(res, 400, { error: 'No fields to update.' });
                return;
            }
            fields.push('updated_at = CURRENT_TIMESTAMP');

            const sql = `UPDATE users SET ${fields.join(', ')} WHERE id = ?`;
            values.push(user.id);

            await db.run(sql, values);
            sendJsonResponse(res, 200, { message: 'Profile updated successfully.' });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // Profile password change endpoint
    if (req.method === 'PUT' && req.url === '/profile/password') {
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            const data = await parseJsonBody(req);
            const { oldPassword, newPassword } = data;

            // Validate input
            if (!oldPassword || !newPassword) {
                sendJsonResponse(res, 400, { error: 'Old password and new password are required.' });
                return;
            }

            // Check if oldPassword and newPassword are strings
            if (typeof oldPassword !== 'string' || typeof newPassword !== 'string') {
                sendJsonResponse(res, 400, { error: 'Old password and new password must be strings.' });
                return;
            }

            // UNCOMMENT AFTER DEVELOPMENT
            // // Validate password strength
            // const passwordError = validatePasswordStrength(newPassword);
            // if (passwordError) {
            //     sendJsonResponse(res, 400, { error: passwordError });
            //     return;
            // }

            // Fetch user from the database
            const userRecord = await db.get(
                `SELECT * FROM users WHERE id = ?`,
                [user.id]
            );
            if (!userRecord) {
                sendJsonResponse(res, 404, { error: 'User not found.' });
                return;
            }

            // Verify old password
            const isOldPasswordValid = await bcrypt.compare(oldPassword, userRecord.password_hash);
            if (!isOldPasswordValid) {
                sendJsonResponse(res, 401, { error: 'Invalid old password.' });
                return;
            }

            // Check if new password is the same as old password
            const isNewPasswordSame = await bcrypt.compare(newPassword, userRecord.password_hash);
            if (isNewPasswordSame) {
                sendJsonResponse(res, 400, { error: 'New password cannot be the same as old password.' });
                return;
            }

            // Hash new password and update in the database
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            await db.run(
                `UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                [hashedNewPassword, user.id]
            );

            sendJsonResponse(res, 200, { message: 'Password updated successfully.' });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error parsing JSON:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // END USER MANAGEMENT ENDPOINTS

    // START PUBLIC USERS ENDPOINT

    // PUBLIC User Endpoint with pagination
    if (req.method === 'GET' && req.url === '/users') {
        try {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const page = parseInt(url.searchParams.get('page') || '1', 10);
            const limit = parseInt(url.searchParams.get('limit') || '10', 10);
            const search = url.searchParams.get('search') || '';
            const offset = (page - 1) * limit;

            let users, totalUsers;
            if (search) {
                const searchPattern = `%${search.toLocaleLowerCase()}%`;
                users = await db.all(
                    `SELECT id, username, bio, avatar FROM users WHERE LOWER(username) LIKE ? LIMIT ? OFFSET ?`,
                    [searchPattern, limit, offset]
                );
                totalUsers = await db.get(
                    `SELECT COUNT(*) as count FROM users WHERE LOWER(username) LIKE ?`,
                    [searchPattern]
                );
            } else {
                users = await db.all(
                `SELECT id, username, bio, avatar FROM users LIMIT ? OFFSET ?`,
                [limit, offset]
            );
                totalUsers = await db.get(`SELECT COUNT(*) as count FROM users`);
            }

            const totalPages = Math.ceil(totalUsers.count / limit);

            sendJsonResponse(res, 200, {
                users,
                page,
                limit,
                totalUsers: totalUsers.count,
                totalPages
            });
        } catch (err: unknown) {
            console.error('Error fetching users:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // PUBLIC User Profiles
    if (req.method === 'GET' && /^\/users\/[a-zA-Z0-9_]{3,20}$/.test(new URL(req.url || '/', `http://${req.headers.host}`).pathname)) {

        try {
        const urlObj = new URL(req.url || '/', `http://${req.headers.host}`);
        const pathParts = urlObj.pathname.split('/').filter(Boolean);
        const username = pathParts[1];
        if (!username) {
            sendJsonResponse(res, 400, { error: 'Username is required.' });
            return;
        }

        if (username.length < 3 || username.length > 20) {
            sendJsonResponse(res, 400, { error: 'Username must be between 3 and 20 characters long.' });
            return;
        }

        if (typeof username !== 'string') {
            sendJsonResponse(res, 400, { error: 'Username must be a string.' });
            return;
        }

        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            sendJsonResponse(res, 400, { error: 'Username can only contain alphanumeric characters and underscores.' });
            return;
        }
    
        // Fetch user profile by username
        const profile = await db.get(
            `SELECT id, username, bio, avatar FROM users WHERE LOWER(username) = ?`,
            [username.toLowerCase()]
        );

        if (!profile) {
            sendJsonResponse(res, 404, { error: 'User not found.' });
            return;
        }

        sendJsonResponse(res, 200, profile);
        } catch (err: unknown) {
            console.error('Error fetching user profile:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // END PUBLIC USERS ENDPOINT

    // START FOLLOW ENDPOINTS

    // Follow User endpoints

    // Follow a user
    if (req.method === 'POST' && /^\/users\/[a-zA-Z0-9_]{3,20}\/follow$/.test(new URL(req.url || '/', `http://${req.headers.host}`).pathname)){
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            const urlObj = new URL(req.url || '/', `http://${req.headers.host}`);
            const pathParts = urlObj.pathname.split('/').filter(Boolean);
            const followedUsername = pathParts[1];

            if (followedUsername.toLowerCase() === user.username.toLowerCase()) {
                sendJsonResponse(res, 400, { error: 'You cannot follow/unfollow yourself.' });
                return;
            }

            const isEmailVerified = await requireEmailVerified(req as VerifiedRequest, res);
            if (!isEmailVerified) return;

            if (!followedUsername) {
                sendJsonResponse(res, 400, { error: 'Username to follow is required.' });
                return;
            }

            if (followedUsername.length < 3 || followedUsername.length > 20) {
                sendJsonResponse(res, 400, { error: 'Username must be between 3 and 20 characters long.' });
                return;
            }

            if (typeof followedUsername !== 'string') {
                sendJsonResponse(res, 400, { error: 'Username must be a string.' });
                return;
            }

            if (!/^[a-zA-Z0-9_]+$/.test(followedUsername)) {
                sendJsonResponse(res, 400, { error: 'Username can only contain alphanumeric characters and underscores.' });
                return;
            }

            // Fetch followed user by username
            const followedUser = await db.get(
                `SELECT id FROM users WHERE LOWER(username) = ?`,
                [followedUsername.toLowerCase()]
            );

            if (!followedUser) {
                sendJsonResponse(res, 404, { error: 'User to follow not found.' });
                return;
            }

            // Check if already following
            const existingFollow = await db.get(
                `SELECT * FROM followers WHERE follower_id = ? AND followed_id = ?`,
                [user.id, followedUser.id]
            );

            if (existingFollow) {
                sendJsonResponse(res, 400, { error: 'You are already following this user.' });
                return;
            }

            // Insert follow relationship into the database
            await db.run(
                `INSERT INTO followers (follower_id, followed_id) VALUES (?, ?)`,
                [user.id, followedUser.id]
            );

            // count the number of followers after following
            const followerCount = await db.get(
                `SELECT COUNT(*) as count FROM followers WHERE followed_id = ?`,
                [followedUser.id]
            );

            sendJsonResponse(res, 201, { message: `You are now following ${followedUsername.toLowerCase()}.`, followerCount: followerCount.count });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error following user:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // Unfollow a user
    if (req.method === 'DELETE' && /^\/users\/[a-zA-Z0-9_]{3,20}\/follow$/.test(new URL(req.url || '/', `http://${req.headers.host}`).pathname)){
        try {
            const user = await authenticateJWT(req, res);
            if (!user) return;

            const urlObj = new URL(req.url || '/', `http://${req.headers.host}`);
            const pathParts = urlObj.pathname.split('/').filter(Boolean);
            const followedUsername = pathParts[1];

            if (followedUsername.toLowerCase() === user.username.toLowerCase()) {
                sendJsonResponse(res, 400, { error: 'You cannot follow/unfollow yourself.' });
                return;
            }

            const isEmailVerified = await requireEmailVerified(req as VerifiedRequest, res);
            if (!isEmailVerified) return;

            if (!followedUsername) {
                sendJsonResponse(res, 400, { error: 'Username to unfollow is required.' });
                return;
            }

            if (followedUsername.length < 3 || followedUsername.length > 20) {
                sendJsonResponse(res, 400, { error: 'Username must be between 3 and 20 characters long.' });
                return;
            }

            if (typeof followedUsername !== 'string') {
                sendJsonResponse(res, 400, { error: 'Username must be a string.' });
                return;
            }

            if (!/^[a-zA-Z0-9_]+$/.test(followedUsername)) {
                sendJsonResponse(res, 400, { error: 'Username can only contain alphanumeric characters and underscores.' });
                return;
            }

            // Fetch followed user by username
            const followedUser = await db.get(
                `SELECT id FROM users WHERE LOWER(username) = ?`,
                [followedUsername.toLowerCase()]
            );

            if (!followedUser) {
                sendJsonResponse(res, 404, { error: 'User to unfollow not found.' });
                return;
            }

            // Check if not following
            const existingFollow = await db.get(
                `SELECT * FROM followers WHERE follower_id = ? AND followed_id = ?`,
                [user.id, followedUser.id]
            );

            if (!existingFollow) {
                sendJsonResponse(res, 400, { error: 'You are not following this user.' });
                return;
            }

            // Delete follow relationship from the database
            await db.run(
                `DELETE FROM followers WHERE follower_id = ? AND followed_id = ?`,
                [user.id, followedUser.id]
            );

            // count the number of followers after unfollowing
            const followerCount = await db.get(
                `SELECT COUNT(*) as count FROM followers WHERE followed_id = ?`,
                [followedUser.id]
            );

            sendJsonResponse(res, 200, { message: `You have unfollowed ${followedUsername.toLowerCase()}.`, followerCount: followerCount.count });
        } catch (err: unknown) {
            if (err instanceof Error && err.message === 'Invalid JSON') {
                handleError(res, 400, 'Invalid JSON format.', err);
            } else {
                console.error('Error unfollowing user:', err);
                handleError(res, 500, 'Internal server error.', err);
            }
            return;
        }
        return;
    }

    // list followers of a user with pagination
    if (req.method === 'GET' && /^\/users\/[a-zA-Z0-9_]{3,20}\/followers$/.test(new URL(req.url || '/', `http://${req.headers.host}`).pathname)) {
        try {
            const urlObj = new URL(req.url || '/', `http://${req.headers.host}`);
            const pathParts = urlObj.pathname.split('/').filter(Boolean);
            const followedUsername = pathParts[1];
            if (!followedUsername) {
                sendJsonResponse(res, 400, { error: 'Username is required.' });
                return;
            }

            if (followedUsername.length < 3 || followedUsername.length > 20) {
                sendJsonResponse(res, 400, { error: 'Username must be between 3 and 20 characters long.' });
                return;
            }

            if (typeof followedUsername !== 'string') {
                sendJsonResponse(res, 400, { error: 'Username must be a string.' });
                return;
            }

            if (!/^[a-zA-Z0-9_]+$/.test(followedUsername)) {
                sendJsonResponse(res, 400, { error: 'Username can only contain alphanumeric characters and underscores.' });
                return;
            }

            // Fetch followed user by username
            const followedUser = await db.get(
                `SELECT id FROM users WHERE LOWER(username) = ?`,
                [followedUsername.toLowerCase()]
            );

            if (!followedUser) {
                sendJsonResponse(res, 404, { error: 'User not found.' });
                return;
            }

            const page = parseInt(urlObj.searchParams.get('page') || '1', 10);
            const limit = parseInt(urlObj.searchParams.get('limit') || '10', 10);
            const offset = (page - 1) * limit;

            // Fetch followers of the user
            const followers = await db.all(
                `SELECT u.id, u.username, u.bio, u.avatar FROM followers f JOIN users u ON f.follower_id = u.id WHERE f.followed_id = ? LIMIT ? OFFSET ?`,
                [followedUser.id, limit, offset]
            );

            // Count total followers
            const totalFollowers = await db.get(
                `SELECT COUNT(*) as count FROM followers WHERE followed_id = ?`,
                [followedUser.id]
            );

            const totalPages = Math.ceil(totalFollowers.count / limit);

            sendJsonResponse(res, 200, {
                followers,
                page,
                limit,
                totalFollowers: totalFollowers.count,
                totalPages
            });
        } catch (err: unknown) {
            console.error('Error fetching followers:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // list following of a user with pagination
    if (req.method === 'GET' && /^\/users\/[a-zA-Z0-9_]{3,20}\/following$/.test(new URL(req.url || '/', `http://${req.headers.host}`).pathname)) {
        try {
            const urlObj = new URL(req.url || '/', `http://${req.headers.host}`);
            const pathParts = urlObj.pathname.split('/').filter(Boolean);
            const followedUsername = pathParts[1];
            if (!followedUsername) {
                sendJsonResponse(res, 400, { error: 'Username is required.' });
                return;
            }

            if (followedUsername.length < 3 || followedUsername.length > 20) {
                sendJsonResponse(res, 400, { error: 'Username must be between 3 and 20 characters long.' });
                return;
            }

            if (typeof followedUsername !== 'string') {
                sendJsonResponse(res, 400, { error: 'Username must be a string.' });
                return;
            }

            if (!/^[a-zA-Z0-9_]+$/.test(followedUsername)) {
                sendJsonResponse(res, 400, { error: 'Username can only contain alphanumeric characters and underscores.' });
                return;
            }

            // Fetch followed user by username
            const followedUser = await db.get(
                `SELECT id FROM users WHERE LOWER(username) = ?`,
                [followedUsername.toLowerCase()]
            );

            if (!followedUser) {
                sendJsonResponse(res, 404, { error: 'User not found.' });
                return;
            }

            const page = parseInt(urlObj.searchParams.get('page') || '1', 10);
            const limit = parseInt(urlObj.searchParams.get('limit') || '10', 10);
            const offset = (page - 1) * limit;

            // Fetch following of the user
            const following = await db.all(
                `SELECT u.id, u.username, u.bio, u.avatar FROM followers f JOIN users u ON f.followed_id = u.id WHERE f.follower_id = ? LIMIT ? OFFSET ?`,
                [followedUser.id, limit, offset]
            );

            // Count total following
            const totalFollowing = await db.get(
                `SELECT COUNT(*) as count FROM followers WHERE follower_id = ?`,
                [followedUser.id]
            );

            const totalPages = Math.ceil(totalFollowing.count / limit);
            sendJsonResponse(res, 200, {
                following,
                page,
                limit,
                totalFollowing: totalFollowing.count,
                totalPages
            });
        } catch (err: unknown) {
            console.error('Error fetching following:', err);
            handleError(res, 500, 'Internal server error.', err);
            return;
        }
        return;
    }

    // END FOLLOW ENDPOINTS

    // Fallback for unsupported methods or routes
    sendJsonResponse(res, 404, { error: 'Not Found' });
    return;
});

// Initialize the database
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});