import * as http from 'http';
import dotenv from 'dotenv';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { dbPromise } from './db';

dotenv.config();

// Parse JSON body from the request
const parseJsonBody = (req: http.IncomingMessage): Promise<any> => {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch (err) {
                reject(new Error('Invalid JSON'));
            }
        });
        req.on('error', err => {
            reject(err);
        });
    });
};

// Send JSON response with the specified status code and data
const sendJsonResponse = (res: http.ServerResponse, statusCode: number, data: object) => {
    if (res.headersSent) return
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
};

// Error handling helper function
const handleError = (res: http.ServerResponse, statusCode: number, error: string, logError?: unknown) => {
    if (logError) {
        console.error(logError);
    }
    sendJsonResponse(res, statusCode, { error });
};

// Password Strength Checker
const validatePasswordStrength = (password: string): string | null => {
    // Example: at least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
    if (password.length < 8) {
        return 'Password must be at least 8 characters long';
    }
    if (!/[A-Z]/.test(password)) {
        return 'Password must contain at least one uppercase letter';
    }
    if (!/[a-z]/.test(password)) {
        return 'Password must contain at least one lowercase letter';
    }
    if (!/[0-9]/.test(password)) {
        return 'Password must contain at least one number';
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        return 'Password must contain at least one special character';
    }
    return null; // valid
}

// Nodemailer configuration
if (!process.env.SMTP_HOST || !process.env.SMTP_PORT || !process.env.EMAIL_FROM) {
    throw new Error('SMTP configuration is not set. Please check your environment variables.');
}

const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
});

// verification email function
const sendVerificationEmail = async (user: { email: string; username: string; verificationToken: string }) => {
    const verifyUrl = `${process.env.APP_URL}/auth/verify-email?token=${user.verificationToken}`;
    await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: 'Verify your email',
        text: `Welcome ${user.username},\n\nPlease verify your email by clicking the link below:\n${verifyUrl}\n\nThis link will expire in 24 hours.`,
        html: `<p>Welcome ${user.username},</p>
               <p>Please verify your email by clicking the link below:</p>
               <a href="${verifyUrl}">Verify Email</a>
               <p>This link will expire in 24 hours.</p>`,
    });
};

// Password reset email function
const sendPasswordResetEmail = async (user: { email: string; username: string; resetUrl: string }) => {
    await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: 'Password Reset Request',
        text: `Hello ${user.username},\n\nYou requested a password reset. Click the link below to reset your password:\n${user.resetUrl}\n\nThis link will expire in 1 hour.`,
        html: `<p>Hello ${user.username},</p>
               <p>You requested a password reset. Click the link below to reset your password:</p>
               <a href="${user.resetUrl}">Reset Password</a>
               <p>This link will expire in 1 hour.</p>`,
    });
};

// send 2fa code email function
const send2FACodeEmail = async (user: { email: string; username: string; code: string }) => {
    await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: 'Your 2FA Code',
        text: `Hello ${user.username},\n\nYour 2FA code is: ${user.code}\n\nThis code will expire in 5 minutes.`,
        html: `<p>Hello ${user.username},</p>
               <p>Your 2FA code is: <strong>${user.code}</strong></p>
               <p>This code will expire in 5 minutes.</p>`,
    });
};

// sanitize content function
const sanitizeContent = (input: string): string => {
    // Trim whitespace
    let sanitized = input.trim();

    // Remove script tags (basic XSS protection)
    sanitized = sanitized.replace(/<script.*?>.*?<\/script>/gi, '');

    // Optionally, escape HTML special characters
    sanitized = sanitized
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    return sanitized;
};

// Generate Refresh Token
const generateRefreshToken = (): string => {
    return crypto.randomBytes(64).toString('hex');
};

// Hash Token
const hashToken = (token: string): string => {
    return crypto.createHash('sha256').update(token).digest('hex');
};

// generate 6 digit 2fa code
const generate2FACode = async (userId: number): Promise<string> => {
    const db = await dbPromise;
    // Clean up expired codes
    await db.run(`DELETE FROM two_factor_codes WHERE expires_at < ?`, [new Date().toISOString()]);

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // Optionally delete old codes for this user
    await db.run(`DELETE FROM two_factor_codes WHERE user_id = ?`, [userId]);

    await db.run(
        `INSERT INTO two_factor_codes (user_id, code, expires_at) VALUES (?, ?, ?)`,
        [userId, code, expiresAt]
    );
    return code;
};


export { 
    parseJsonBody, 
    sendJsonResponse, 
    handleError, 
    validatePasswordStrength, 
    sendVerificationEmail, 
    sendPasswordResetEmail, 
    send2FACodeEmail,
    transporter,
    sanitizeContent,
    generateRefreshToken,
    generate2FACode,
    hashToken
};