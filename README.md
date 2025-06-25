# User Service - Connected Healthcare Ecosystem

<div align="center">

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

*A secure, compliant microservice for user management in healthcare*

[Features](#features) • [Quick Start](#quick-start) • [API Endpoints](#api-endpoints) • [Contributing](#contributing)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Docker Setup](#docker-setup)
- [API Endpoints](#api-endpoints)
- [Security & Compliance](#security--compliance)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Environment Variables](#environment-variables)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## Overview

The **User Service** is a microservice within the Connected Healthcare Ecosystem, managing user authentication, KYC verification, and profile management for patients, doctors, labs, pharmacies, and admins. Built with Node.js, Express, and MongoDB, it ensures compliance with **NDHM**, **DPDP Act**, and **Telemedicine Guidelines**, supporting offline-first operations, scalability, and robust security.

---

## Features

- **Authentication**:
  - Register/login with JWT (access: 1h, refresh: 30d).
  - Password reset via email (10-min token expiry).
  - Role-based access (patient, doctor, lab, pharmacy, admin).
- **KYC Verification**:
  - Doctors upload Aadhar/PAN/license to Cloudinary (encrypted).
  - Admins verify/reject KYC with notifications.
  - Audit logs for compliance.
- **Profile Management**:
  - View/update profile (name, phone, address).
  - Soft-delete accounts.
- **Security**:
  - Rate limiting (100 reqs/15 min), Helmet headers, Joi validation.
  - Secure inter-service calls with `SERVICE_KEY`.
- **Logging**:
  - Winston-based audit logs for all actions.
- **Offline-First**:
  - Core auth/profile works with local MongoDB (KYC needs internet).
- **Testing**:
  - Unit tests for auth endpoints using Jest and MongoMemoryServer.

---

## Quick Start

### Prerequisites
- Node.js v18+
- MongoDB (local or Atlas)
- Cloudinary account
- Git

### Installation
1. **Clone Repository**:
   ```bash
   git clone https://github.com/shoaibkhan188626/user-service.git
   cd user-service
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Configure `.env`**:
   ```bash
   cp .env.example .env
   nano .env  # Edit with your credentials
   ```

4. **Start Server**:
   ```bash
   npm run dev  # Development with hotfix
   npm start    # Production
   ```

5. **Run Mock Services**:
   ```bash
   node mock-hospital.js      # Port 8080
   node mock-notification.js  # Port 8081
   ```

6. **Verify**:
   ```bash
   curl http://localhost:5001/health
   ```

---

## Docker Setup

1. **Build Image**:
   ```bash
   docker build -t user-service .
   ```

2. **Run Container**:
   ```bash
   docker run -p 5001:5001 --env-file .env user-service
   ```

---

## API Endpoints

### Authentication (`/api/auth`)
| Method | Endpoint            | Description                | Auth Required |
|--------|---------------------|----------------------------|---------------|
| `POST` | `/register`         | Register user              | ❌            |
| `POST` | `/login`            | Login user                 | ❌            |
| `POST` | `/logout`           | Logout user                | ✅            |
| `POST` | `/password-reset`   | Request password reset     | ❌            |
| `POST` | `/reset`            | Reset password             | ❌            |
| `POST` | `/refresh`          | Refresh access token       | ❌            |

### KYC (`/api/kyc`)
| Method | Endpoint    | Description                | Auth Required | Role  |
|--------|-------------|----------------------------|---------------|-------|
| `POST` | `/upload`   | Upload KYC documents       | ✅            | Doctor |
| `POST` | `/verify`   | Verify/reject KYC          | ✅            | Admin  |

### User (`/api/users`)
| Method  | Endpoint    | Description                | Auth Required |
|---------|-------------|----------------------------|---------------|
| `GET`   | `/profile`  | Get profile                | ✅            |
| `PATCH` | `/profile`  | Update profile             | ✅            |
| `DELETE`| `/profile`  | Soft-delete account        | ✅            |

**Example: Register User**
```bash
curl -X POST http://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Dr. Priya","email":"priya@example.com","phone":"9876543210","password":"Secure@123","role":"doctor","hospitalId":"507f191e810c19729de860ea"}'
```

---

## Security & Compliance

- **NDHM**:
  - Audit logs for all actions.
  - Interoperable data standards.
- **DPDP Act**:
  - Encrypted Cloudinary storage.
  - Minimal data retention, soft deletes.
- **Telemedicine Guidelines**:
  - Mandatory KYC for doctors (blocks unverified access).
  - Admin verification with rejection reasons.
- **Security**:
  - JWT with bcrypt hashing.
  - Rate limiting, Helmet, CORS protection.
  - Joi validation to prevent injection.

---

## Testing

1. **Run Tests**:
   ```bash
   npm test
   ```

2. **Test Suite**:
   - `tests/auth.test.js`: Auth endpoint tests with MongoMemoryServer.
   - Future: Add KYC and user tests.

3. **Coverage**:
   - Goal: >90% for critical endpoints.

---

## Project Structure

```
user-service/
├── .env                    # Environment variables
├── README.md               # Documentation
├── app.js                  # Express setup
├── config/                 # Configuration
│   ├── database.js         # MongoDB connection
│   └── logger.js           # Winston logging
├── controllers/            # API logic
│   ├── auth.controller.js  # Auth endpoints
│   ├── kyc.controller.js   # KYC endpoints
│   └── user.controller.js  # User endpoints
├── jobs/                   # Cron jobs
│   └── cleanup.js          # Token cleanup
├── middlewares/            # Request processing
│   ├── ErrorHandler.js     # Error handling
│   ├── auth.middleware.js  # JWT verification
│   └── logger.middleware.js# Request logging
├── models/                 # Schemas
│   └── user.js             # User schema
├── routes/                 # API routes
│   ├── auth.routes.js      # Auth routes
│   ├── kyc.routes.js       # KYC routes
│   └── user.routes.js      # User routes
├── services/               # Business logic
│   └── user.service.js     # User operations
├── tests/                  # Tests
│   └── auth.test.js        # Auth tests
├── utils/                  # Utilities
│   ├── crypto.js           # Token generation
│   ├── error.js            # Custom errors
│   ├── httpClient.js       # HTTP client
│   └── validate.js         # Joi validation
├── validations/            # Validation schemas
│   └── auth.validation.js  # Auth schemas
├── package-lock.json       # Dependency lock
├── package.json            # Project metadata
├── server.js               # Server startup
```

---

## Environment Variables

```bash
NODE_ENV=development
PORT=5001
MONGO_URI_LOCAL=mongodb://localhost:27017/user-service
MONGO_URI_ATLAS=mongodb+srv://<user>:<pass>@cluster0.mongodb.net/user-service
JWT_SECRET=your-secure-jwt-secret-32-chars
JWT_REFRESH_SECRET=your-refresh-jwt-secret-64-chars
HOSPITAL_SERVICE_URL=http://localhost:8080
NOTIFICATION_SERVICE_URL=http://localhost:8081
SERVICE_KEY=a7b9c2d8e4f0g1h2i3j4k5l6m7n8o9p0q1r2s3t4
FRONTEND_URL=http://localhost:3000
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

---

## Contributing

1. **Fork** the repo: `https://github.com/shoaibkhan188626/user-service.git`
2. Create a branch: `git checkout -b feature/<name>`
3. Commit changes: `git commit -m "Add feature"`
4. Run tests: `npm test`
5. Push and open a PR.

**Standards**:
- Use ESLint/Prettier.
- Write tests for new features.
- Update README if needed.

---

## License

MIT License © 2025 Connected Healthcare Ecosystem

See [LICENSE](LICENSE) for details.

---

## Support

- **Email**: shoaibullakhan15@gmail.com
- **Issues**: Open a GitHub issue for bugs or features.

---

<div align="center">

**[⬆ Back to Top](#user-service---connected-healthcare-ecosystem)**

Built with ❤️ by Shoaib Khan

</div>