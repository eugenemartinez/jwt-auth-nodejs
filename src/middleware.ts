import jwt from 'jsonwebtoken';
import http from 'http';
import dotenv from 'dotenv';
import { sendJsonResponse } from './utils';
import { dbPromise } from './db';
import { RateLimiterMemory, RateLimiterRedis } from 'rate-limiter-flexible';
import Redis from 'ioredis';

dotenv.config();

// Ensure JWT secret is set in environment variables
const jwtSecret = process.env.JWT_SECRET as string;
if (!jwtSecret) {
    throw new Error('JWT_SECRET is not set in the environment variables.');
}

// Rate limiter configuration
let rateLimiter: RateLimiterMemory | RateLimiterRedis;
if (process.env.REDIS_URL) {
    const redis = new Redis(process.env.REDIS_URL);
    rateLimiter = new RateLimiterRedis({
        storeClient: redis,
        keyPrefix: 'rateLimiter',
        points: 20, // 10 requests
        duration: 60, // per minute
        blockDuration: 60, // block for 1 minute if limit exceeded
    });
    console.log('Using Redis for rate limiting');
} else {
    rateLimiter = new RateLimiterMemory({
        points: 20, // 10 requests
        duration: 60, // per minute
        blockDuration: 60, // block for 1 minute if limit exceeded
    });
    console.log('Using in-memory rate limiting');
}

interface VerifiedUser {
    id: string;
    username: string;
    email: string;
    email_verified: boolean;
    iat: number;
    exp: number;
}

interface VerifiedRequest extends http.IncomingMessage {
    user?: VerifiedUser;
}

// Auth middleware for verifying JWT and attaching user info to the request
const authenticateJWT = (req: http.IncomingMessage, res: http.ServerResponse): Promise<VerifiedUser | null> => {
    return new Promise((resolve, reject) => {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            sendJsonResponse(res, 401, { error: 'Missing or invalid Authorization header.' });
            resolve(null);
            return;
        }

        const token = authHeader.split(' ')[1];
        jwt.verify(token, jwtSecret, (err, decoded) => {
            if (err) {
                sendJsonResponse(res, 401, { error: 'Invalid or expired token.' });
                resolve(null);
                return;
            }
            // Attach user info to the request (optional, for further use)
            (req as VerifiedRequest).user = decoded as VerifiedUser;
            resolve(decoded as VerifiedUser);
        });
    });
}

// Require email verified middleware
const requireEmailVerified = async (req: VerifiedRequest, res: http.ServerResponse): Promise<boolean> => {
    const db = await dbPromise;
    // Fetch user from DB to ensure latest status
    const dbUser = await db.get(`SELECT email_verified FROM users WHERE id = ?`, [req.user?.id]);
    if (!dbUser || !dbUser.email_verified) {
        sendJsonResponse(res, 403, { error: 'Email not verified.' });
        return false;
    }
    return true;
};

// 2fa code verification middleware
const verify2FACode = async (userId: number, code: string, res: http.ServerResponse): Promise<boolean> => {
    const db = await dbPromise;
    // Clean up expired codes
    await db.run(`DELETE FROM two_factor_codes WHERE expires_at < ?`, [new Date().toISOString()]);

    const dbCode = await db.get(`SELECT * FROM two_factor_codes WHERE user_id = ? AND code = ?`, [userId, code]);
    if (!dbCode || new Date(dbCode.expires_at) < new Date()) {
        sendJsonResponse(res, 403, { error: 'Invalid or expired 2FA code.' });
        return false;
    }
    await db.run(`DELETE FROM two_factor_codes WHERE id = ?`, [dbCode.id]);
    return true;
};

// rate limiting middleware
const rateLimitMiddleware = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<boolean> => {
    const ip = req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress || '';
    try {
        await rateLimiter.consume(ip);
        return true;
    } catch {
        sendJsonResponse(res, 429, { error: 'Too many requests. Please try again later.' });
        return false;
    }
};

export { 
    jwtSecret, 
    authenticateJWT, 
    requireEmailVerified, 
    verify2FACode, 
    VerifiedRequest, 
    rateLimitMiddleware 
};