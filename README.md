# 🔐 Enterprise Grade JWT 2FA Authentication System

A production-ready, feature-rich authentication system built with Django REST Framework and JWT. This system provides enterprise-level security features including device tracking, login history, session management, and email verification.

## 📋 Table of Contents
- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [System Architecture](#-system-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [API Endpoints](#-api-endpoints)
- [Security Features](#-security-features)
- [Device Tracking](#-device-tracking)
- [Login History](#-login-history)
- [Session Management](#-session-management)
- [Error Handling](#-error-handling)
- [Docker Deployment](#-docker-deployment)
- [Testing](#-testing)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### Core Authentication
- ✅ **JWT Authentication** - Secure access and refresh token mechanism
- ✅ **Email Verification** - OTP-less email verification with time-limited tokens
- ✅ **Password Reset** - Secure password reset via email with expiring links
- ✅ **Account Lockout** - Automatic account locking after 5 failed login attempts
- ✅ **Rate Limiting** - Protection against brute-force attacks

### Security Features
- ✅ **Device Fingerprinting** - Track unique devices accessing the account
- ✅ **Browser & OS Detection** - Identify browser name, version, and operating system
- ✅ **IP Address Tracking** - Log IP addresses for all login attempts
- ✅ **Session Management** - View and revoke active sessions remotely
- ✅ **Token Blacklisting** - Invalidate tokens on logout
- ✅ **Login History** - Complete audit trail of all login activities
- ✅ **Failed Login Tracking** - Monitor and analyze failed login attempts

### Advanced Features
- ✅ **Celery Integration** - Asynchronous email processing
- ✅ **Redis Caching** - High-performance token and session caching
- ✅ **Rate Limiting** - Per-endpoint request throttling
- ✅ **Sentry Integration** - Production error tracking and monitoring
- ✅ **Docker Support** - Containerized deployment ready
- ✅ **PostgreSQL** - Robust relational database with indexes

### Monitoring & Analytics
- ✅ **Login Analytics** - Track login patterns and anomalies
- ✅ **Device History** - See all devices that accessed the account
- ✅ **Location Tracking** - Geo-IP integration (optional)
- ✅ **User Agent Parsing** - Detailed device and browser information

## 🛠 Technology Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Core programming language |
| Django | 4.2 | Web framework |
| Django REST Framework | 3.14 | API development |
| Simple JWT | 5.3 | JWT authentication |
| PostgreSQL | 15 | Production database |
| Redis | 7 | Cache & message broker |
| Celery | 5.3 | Background tasks |
| Gunicorn | 21.2 | WSGI HTTP server |
| Docker | Latest | Containerization |
| Sentry | Latest | Error monitoring |

## 🏗 System Architecture
