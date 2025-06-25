# 🏥 User Service - Connected Healthcare Ecosystem

<div align="center">

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

*A robust, secure, and compliant microservice for healthcare user management*

[Features](#-features) • [Quick Start](#-quick-start) • [API Documentation](#-api-documentation) • [Contributing](#-contributing)

</div>

---

## 📋 Table of Contents

- [🌟 Overview](#-overview)
- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🚀 Quick Start](#-quick-start)
- [🐳 Docker Setup](#-docker-setup)
- [📚 API Documentation](#-api-documentation)
- [🔐 Security & Compliance](#-security--compliance)
- [🧪 Testing](#-testing)
- [📁 Project Structure](#-project-structure)
- [🛠️ Configuration](#️-configuration)
- [🔄 Development Workflow](#-development-workflow)
- [🚀 Deployment](#-deployment)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## 🌟 Overview

The **User Service** is a mission-critical microservice within the Connected Healthcare Ecosystem, designed to handle user authentication, KYC verification, and profile management for healthcare stakeholders including patients, doctors, laboratories, pharmacies, and administrators.

Built with modern technologies and industry best practices, this service ensures **NDHM compliance**, **DPDP Act adherence**, and **Telemedicine Guidelines** compatibility while maintaining high availability, security, and scalability.

### 🎯 Key Objectives

- **Secure Authentication**: JWT-based authentication with role-based access control
- **Regulatory Compliance**: Full compliance with Indian healthcare regulations
- **Scalable Architecture**: Microservices design for horizontal scaling
- **Offline-First**: Core functionality works without internet connectivity
- **Developer-Friendly**: Comprehensive API documentation and testing suite

---

## ✨ Features

### 🔐 Authentication & Authorization
- **JWT Token Management**: Short-lived access tokens (1h) with long-lived refresh tokens (30d)
- **Role-Based Access Control**: Support for Patient, Doctor, Lab, Pharmacy, and Admin roles
- **Password Security**: Bcrypt hashing with salt rounds
- **Password Reset**: Secure email-based password reset with 10-minute token expiry

### 📋 KYC Verification System
- **Document Upload**: Secure upload of Aadhar, PAN, and Medical License documents
- **Admin Verification**: Streamlined approval/rejection workflow with notifications
- **Encrypted Storage**: Documents stored securely on Cloudinary with encryption
- **Compliance Tracking**: Full audit trail for regulatory compliance

### 👤 Profile Management
- **Comprehensive Profiles**: Manage user information, contact details, and addresses
- **Soft Delete**: Data retention policies with soft deletion capabilities
- **Update Tracking**: Audit logs for all profile modifications

### 🛡️ Security Features
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **Security Headers**: Helmet.js for secure HTTP headers
- **Input Validation**: Joi-based validation for all endpoints
- **CORS Protection**: Configurable CORS policies
- **Service Authentication**: Inter-service communication security

### 📊 Monitoring & Logging
- **Structured Logging**: Winston-based logging with multiple transport options
- **Audit Trails**: Comprehensive audit logging for compliance
- **Error Tracking**: Centralized error handling and reporting
- **Health Checks**: Built-in health monitoring endpoints

---

## 🏗️ Architecture

```mermaid
graph TB
    A[Client Applications] --> B[API Gateway]
    B --> C[User Service]
    C --> D[MongoDB]
    C --> E[Cloudinary]
    C --> F[Hospital Service]
    C --> G[Notification Service]
    
    subgraph "User Service Components"
        H[Authentication Controller]
        I[KYC Controller]
        J[User Controller]
        K[Middleware Layer]
        L[Business Logic]
    end
    
    C --> H
    C --> I
    C --> J
    C --> K
    C --> L
```

---

## 🚀 Quick Start

### Prerequisites

Ensure you have the following installed:

- **Node.js** (v18 or higher)
- **MongoDB** (local installation or Atlas cluster)
- **Git**
- **Cloudinary Account** (for document storage)

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/<your-org>/user-service.git
   cd user-service
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start the Service**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm start
   ```

5. **Verify Installation**
   ```bash
   curl http://localhost:5001/health
   ```

### Mock Services (for Development)

Start the mock services for complete local development:

```bash
# Terminal 1 - Hospital Service Mock
node mock-hospital.js

# Terminal 2 - Notification Service Mock  
node mock-notification.js

# Terminal 3 - User Service
npm start
```

---

## 🐳 Docker Setup

### Build and Run

```bash
# Build the Docker image
docker build -t user-service:latest .

# Run the container
docker run -p 5001:5001 --env-file .env user-service:latest
```

### Docker Compose (Recommended)

```yaml
version: '3.8'
services:
  user-service:
    build: .
    ports:
      - "5001:5001"
    environment:
      - NODE_ENV=production
      - MONGO_URI=${MONGO_URI}
    depends_on:
      - mongodb
  
  mongodb:
    image: mongo:latest
    ports:
      - "27017:27017"
    volumes:
      - mongodb_data:/data/db

volumes:
  mongodb_data:
```

---

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/auth/register` | Register new user | ❌ |
| `POST` | `/api/auth/login` | User login | ❌ |
| `POST` | `/api/auth/logout` | User logout | ✅ |
| `POST` | `/api/auth/refresh` | Refresh access token | ❌ |
| `POST` | `/api/auth/password-reset` | Request password reset | ❌ |
| `POST` | `/api/auth/reset` | Reset password | ❌ |

### KYC Endpoints

| Method | Endpoint | Description | Auth Required | Role |
|--------|----------|-------------|---------------|------|
| `POST` | `/api/kyc/upload` | Upload KYC documents | ✅ | Doctor |
| `POST` | `/api/kyc/verify` | Verify/reject KYC | ✅ | Admin |

### User Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/users/profile` | Get user profile | ✅ |
| `PATCH` | `/api/users/profile` | Update profile | ✅ |
| `DELETE` | `/api/users/profile` | Delete account (soft) | ✅ |

### Example API Usage

#### Register a New User
```bash
curl -X POST http://localhost:5001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Dr. John Doe",
    "email": "john.doe@example.com",
    "phone": "+919876543210",
    "password": "SecurePass123!",
    "role": "doctor",
    "hospitalId": "HOSP001"
  }'
```

#### Login
```bash
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePass123!"
  }'
```

---

## 🔐 Security & Compliance

### Regulatory Compliance

#### NDHM (National Digital Health Mission)
- ✅ Structured health data management
- ✅ Patient consent mechanisms
- ✅ Interoperability standards
- ✅ Audit trail maintenance

#### DPDP Act (Digital Personal Data Protection Act)
- ✅ Data minimization principles
- ✅ Encrypted data storage
- ✅ User consent management
- ✅ Right to data deletion

#### Telemedicine Guidelines
- ✅ Doctor KYC verification mandatory
- ✅ Medical license validation
- ✅ Professional credential checks

### Security Measures

- **🔐 JWT Authentication**: Industry-standard token-based authentication
- **🛡️ Rate Limiting**: Protection against brute force attacks
- **🔒 Data Encryption**: All sensitive data encrypted in transit and at rest
- **📝 Audit Logging**: Comprehensive logging for security monitoring
- **🚫 Input Validation**: Joi-based validation prevents injection attacks
- **🔑 Role-Based Access**: Granular permission system

---

## 🧪 Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Test Structure

```
tests/
├── auth.test.js          # Authentication tests
├── kyc.test.js           # KYC verification tests
├── user.test.js          # User management tests
└── integration/          # Integration tests
    ├── api.test.js
    └── security.test.js
```

### Test Coverage Goals

- **Unit Tests**: > 90% code coverage
- **Integration Tests**: All API endpoints
- **Security Tests**: Authentication and authorization flows
- **Performance Tests**: Load testing for critical endpoints

---

## 📁 Project Structure

```
user-service/
┣ 📂 config/                 # Configuration files
┃ ┣ 📜 database.js           # MongoDB connection setup
┃ ┗ 📜 logger.js             # Winston logging configuration
┣ 📂 controllers/            # Request handlers
┃ ┣ 📜 auth.controller.js    # Authentication logic
┃ ┣ 📜 kyc.controller.js     # KYC verification logic
┃ ┗ 📜 user.controller.js    # User management logic
┣ 📂 middlewares/            # Express middlewares
┃ ┣ 📜 auth.middleware.js    # JWT verification
┃ ┣ 📜 ErrorHandler.js       # Global error handling
┃ ┗ 📜 logger.middleware.js  # Request logging
┣ 📂 models/                 # Database schemas
┃ ┗ 📜 user.js               # User model definition
┣ 📂 routes/                 # API route definitions
┃ ┣ 📜 auth.routes.js        # Authentication routes
┃ ┣ 📜 kyc.routes.js         # KYC routes
┃ ┗ 📜 user.routes.js        # User routes
┣ 📂 services/               # Business logic layer
┃ ┗ 📜 user.service.js       # User operations
┣ 📂 utils/                  # Utility functions
┃ ┣ 📜 crypto.js             # Cryptographic utilities
┃ ┣ 📜 error.js              # Custom error classes
┃ ┣ 📜 httpClient.js         # HTTP client with retry logic
┃ ┗ 📜 validate.js           # Joi validation helpers
┣ 📂 validations/            # Input validation schemas
┃ ┗ 📜 auth.validation.js    # Authentication validations
┣ 📂 tests/                  # Test suites
┃ ┗ 📜 auth.test.js          # Authentication tests
┣ 📂 jobs/                   # Scheduled tasks
┃ ┗ 📜 cleanup.js            # Token cleanup cron job
┣ 📜 app.js                  # Express application setup
┣ 📜 server.js               # Server startup script
┣ 📜 package.json            # Project dependencies
┗ 📜 .env.example            # Environment variables template
```

---

## 🛠️ Configuration

### Environment Variables

Create a `.env` file in the root directory:

```bash
# Server Configuration
NODE_ENV=development
PORT=5001

# Database Configuration
MONGO_URI_LOCAL=mongodb://localhost:27017/user-service
MONGO_URI_ATLAS=mongodb+srv://username:password@cluster.mongodb.net/user-service

# JWT Configuration
JWT_SECRET=your-super-secure-jwt-secret-key-32-characters-minimum
JWT_REFRESH_SECRET=your-super-secure-refresh-secret-64-characters-minimum

# External Services
HOSPITAL_SERVICE_URL=http://localhost:8080
NOTIFICATION_SERVICE_URL=http://localhost:8081
SERVICE_KEY=your-inter-service-communication-key

# Frontend Configuration
FRONTEND_URL=http://localhost:3000

# Cloudinary Configuration
CLOUDINARY_CLOUD_NAME=your-cloudinary-cloud-name
CLOUDINARY_API_KEY=your-cloudinary-api-key
CLOUDINARY_API_SECRET=your-cloudinary-api-secret

# Logging Configuration
LOG_LEVEL=info
LOG_FILE=logs/app.log
```

### Database Configuration

#### Local MongoDB
```bash
# Install MongoDB locally
# Ubuntu/Debian
sudo apt-get install mongodb

# macOS
brew install mongodb-community

# Start MongoDB service
sudo systemctl start mongodb
```

#### MongoDB Atlas
1. Create account at [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Create a new cluster
3. Configure network access and database user
4. Copy connection string to `MONGO_URI_ATLAS`

---

## 🔄 Development Workflow

### Branch Strategy

```bash
main                    # Production-ready code
├── develop            # Integration branch
├── feature/auth       # Feature branches
├── feature/kyc        
├── hotfix/security    # Hotfix branches
└── release/v1.0       # Release branches
```

### Code Quality

```bash
# Linting
npm run lint

# Code formatting
npm run format

# Pre-commit hooks
npm run pre-commit
```

### Development Commands

```bash
# Start development server with hot reload
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run database migrations
npm run migrate

# Seed development data
npm run seed
```

---

## 🚀 Deployment

### Production Checklist

- [ ] Environment variables configured
- [ ] Database connection tested
- [ ] SSL certificates installed
- [ ] Monitoring setup configured
- [ ] Backup strategy implemented
- [ ] Load balancer configured
- [ ] Health checks enabled

### Cloud Deployment Options

#### AWS Deployment
```bash
# Using AWS ECS
aws ecs create-service --service-name user-service

# Using AWS Lambda (serverless)
serverless deploy
```

#### Google Cloud Platform
```bash
# Using Cloud Run
gcloud run deploy user-service --image gcr.io/project/user-service
```

#### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        ports:
        - containerPort: 5001
```

### Monitoring & Observability

- **📊 Metrics**: Prometheus + Grafana
- **📝 Logging**: ELK Stack (Elasticsearch, Logstash, Kibana)
- **🔍 Tracing**: Jaeger for distributed tracing
- **🚨 Alerting**: PagerDuty for critical alerts

---

## 🤝 Contributing

We welcome contributions from the community! Please follow these guidelines:

### Getting Started

1. **Fork the Repository**
   ```bash
   gh repo fork user-service
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Changes**
   - Follow coding standards
   - Add tests for new features
   - Update documentation

4. **Run Tests**
   ```bash
   npm test
   npm run lint
   ```

5. **Submit Pull Request**
   - Clear description of changes
   - Link to related issues
   - Ensure CI passes

### Code Standards

- **ESLint**: Follow configured rules
- **Prettier**: Auto-format code
- **JSDoc**: Document functions and classes
- **Test Coverage**: Maintain >90% coverage

### Issue Reporting

Use GitHub Issues for:
- 🐛 Bug reports
- 💡 Feature requests
- 📖 Documentation improvements
- ❓ Questions and support

---

## 📈 Roadmap

### Version 1.1 (Q2 2025)
- [ ] Swagger/OpenAPI documentation
- [ ] GraphQL API support
- [ ] Advanced audit logging
- [ ] Multi-factor authentication

### Version 1.2 (Q3 2025)
- [ ] Real-time notifications
- [ ] Advanced search capabilities
- [ ] Bulk operations API
- [ ] Performance optimizations

### Version 2.0 (Q4 2025)
- [ ] Microservices orchestration
- [ ] Advanced analytics
- [ ] AI-powered insights
- [ ] Mobile SDK

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Connected Healthcare Ecosystem

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🙏 Acknowledgments

- **Node.js Community** for excellent runtime and ecosystem
- **MongoDB Team** for robust database solution
- **Healthcare Professionals** for domain expertise and requirements
- **Open Source Contributors** for inspiration and best practices

---

## 📞 Support

- **📧 Email**: shoaibullakhan15@gmail.com


---

<div align="center">

**[⬆ Back to Top](#-user-service---connected-healthcare-ecosystem)**

Made with ❤️ by the Connected Healthcare Ecosystem Team

</div>