# Authentication System with Node.js and Passport

This project is a complete authentication system built with Node.js, Express, and MongoDB. It includes user registration, login, password reset, and social authentication using Google OAuth. The system is designed to be a starter template for new applications requiring user authentication.

## Features

- User registration with email and password
- User login with password
- Password reset functionality
- Google OAuth 2.0 authentication
- Session management with `express-session`
- Flash messages for user feedback
- Password hashing with `bcrypt`
- Email sending with `nodemailer`

## Installation

### Prerequisites

- Node.js
- MongoDB
- A Google OAuth 2.0 client ID and secret (for Google authentication)


## Usage

- **Register a new user** at `/signup`
- **Login** at `/login`
- **Reset password** at `/forgot-password`
- **Use Google OAuth** for authentication at `/auth/google`
- **Reset password with a token** at `/reset-password/:token`

## Routes

- `GET /` - Home page
- `GET /login` - Login page
- `POST /login` - Login action
- `GET /signup` - Sign-up page
- `POST /signup` - Sign-up action
- `GET /forgot-password` - Forgot password page
- `POST /forgot-password` - Forgot password action
- `GET /reset-password/:token` - Reset password page
- `POST /reset-password/:token` - Reset password action
- `GET /auth/google` - Google authentication
- `GET /auth/google/callback` - Google OAuth callback
- `GET /logout` - Logout action

