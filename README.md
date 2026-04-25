# Secure Authentication System

Assignment 2 implementation for Data Integrity and Authentication.

## Implemented Features

- User registration with required fields: name, email, password, role.
- Password hashing using `bcryptjs` (never stores plain text passwords).
- Login using email + password.
- Two-factor authentication using TOTP (`speakeasy`) with QR code (`qrcode`).
- JWT token generation after successful password + 2FA.
- Token-protected routes.
- RBAC with exactly 3 roles: `Admin`, `Manager`, `User`.
- Role-protected routes:
  - `/admin` for Admin only
  - `/manager` for Manager only
  - `/profile` and `/user` for User only
- Required pages/APIs:
  - Register, Login, 2FA verification, Dashboard, Profile, Admin, Manager, User
  - `/api/me` protected API example

## Run

1. Install dependencies:

   ```bash
   npm install
   ```

2. Start app:

   ```bash
   npm start
   ```

3. Open:

   - [http://localhost:3000/register](http://localhost:3000/register)

## Demonstration Checklist

1. Register a new user.
2. Show DB file `database.sqlite` stores `password_hash` (not plain password).
3. Show QR code during registration.
4. Login with password and then 2FA code.
5. Show generated JWT token.
6. Access protected routes.
7. Demonstrate all three roles.
8. Demonstrate blocked access for unauthorized role.
