# Minimal Node.js Auth & Profile API

This is a simple Node.js API for user authentication, profile management, 2FA, user listing, and following functionality.  
It uses SQLite for storage and supports JSON API responses.

## Features

- User registration and login (with 2FA via email)
- JWT-based authentication
- Token refresh and rotation
- Password reset via email
- Email verification and resend verification
- Profile management (bio, avatar seed)
- List all users (public endpoint)
- Public user profiles
- Follow/unfollow users
- List followers and following with pagination
- Session management (list, delete, logout, logout all)
- CORS support for frontend integration
- Rate limiting for security

## Getting Started

1. **Install dependencies:**
   ```sh
   npm install
   ```

2. **Set up environment variables:**
   - Copy `.env.example` to `.env` and fill in the required values.

3. **Run the server:**
   ```sh
   npm start
   ```

## API Endpoints

### Authentication
- `POST /auth/register` — Register a new user
- `POST /auth/login` — Login and receive 2FA code
- `POST /auth/login-2fa` — Complete login with 2FA and receive tokens
- `POST /auth/refresh` — Refresh JWT and rotate refresh token
- `POST /auth/logout` — Logout from current session
- `POST /auth/logout-all` — Logout from all sessions
- `POST /auth/verify-email` — Verify email with token
- `POST /auth/resend-verification` — Resend verification email
- `POST /auth/request-password-reset` — Request password reset
- `POST /auth/reset-password` — Reset password

### Sessions
- `GET /sessions` — List user sessions (paginated)
- `DELETE /sessions/:id` — Delete a specific session

### Profile
- `GET /profile` — Get current user's profile (auth required)
- `PUT /profile` — Update profile (bio, avatar)
- `PUT /profile/password` — Change password

### Users & Social
- `GET /users` — List all users (paginated, public)
- `GET /users/:username` — Get public profile by username
- `POST /users/:username/follow` — Follow a user
- `DELETE /users/:username/follow` — Unfollow a user
- `GET /users/:username/followers` — List followers (paginated)
- `GET /users/:username/following` — List following (paginated)

## Notes

- Database is stored as a local `.sqlite` file.
- This project is for learning and demonstration purposes only.

---