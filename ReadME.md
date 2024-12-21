# Authentication Service RestAPI

An authentication service project using Golang and `gin` framework, with MongoDB as the database backend. The service provides the functionality for user registration(sign-up), login(sign-in), and token management through JWT. 

## Project Structure
```
auth-service/
├── api/
│   └── routes/           # Route handlers
├── db/                   # Database configuration
├── internal/
│   ├── verify/          # Authentication middleware functions
│   ├── models/          # Data models
│   └── services/        # API service logic
├── utils/               # Utility functions 
├── .env                 # Environment variables
├── docker-compose.yml   # Docker compose config
└── Dockerfile          # Docker config
```

## How to get started?
The Authentication service can be run as a containerized application using Docker (recommended). 

### 1. Environment Setup

1. Create a `.env` file in the root directory of the project similar to `.env.example`
2. Docker & Docker compose installed
3. Go 1.21 or higher (if running locally)
4. MongoDB (if running locally)

### 2. Running the service

using Docker-compose:
```bash
docker-compose up --build
```
This command builds and starts both the API service and MongoDB.     
To stop the services, use:
```bash
docker-compose down
```

## API documentation

The service exposes RESTful endpoints for user authentication and token management. Here's how to interact with each endpoint using curl commands (formatted for Windows PowerShell):

### 1. User Sign-Up

```powershell
curl -X POST http://localhost:8080/auth/signup -H "Content-Type: application/json" -d '{"email": "user1.test@example.com", "password": "password123"}'
```
#### Successful Signup Response
```json
{
    "id": "user_id",
    "email": "test@example.com",
    "created_at": "2025-01-01T00:00:01Z",
    "updated_at": "2025-01-01T00:00:10Z"
}
```

### 2. User Sign-In
```powershell
curl -X POST http://localhost:8080/auth/signin -H "Content-Type: application/json" -d '{"email": "user1.test@example.com", "password": "password123"}'
```
#### Successful Signin Response
```json
{
    "access_token": "eyJKngGc...",
    "refresh_token": "eyKmvTo..."
}
```

### 3. Token Operations
After signing in, you'll receive an access token and refresh token. Store the access token in a variable for subsequent requests:
```powershell
$ACCESS_TOKEN="<received_access_token>"
$REFRESH_TOKEN="<refresh_token_here>"
```

Protected Profile Access
```powershell
curl -X GET http://localhost:8080/protected/profile -H "Authorization: Bearer $ACCESS_TOKEN"
```

Token Revocation
```powershell
curl -X POST http://localhost:8080/auth/revoke -H "Authorization: Bearer $ACCESS_TOKEN"
```

Refresh expired token
```powershell
curl -X POST http://localhost:8080/auth/refresh -H "X-Refresh-Token: $REFRESH_TOKEN"
```

## Testing
Test coverage for core functionalities, Test scripts are written for token utilities (`token_test.go`), authentication services (`user_service_test.go`), and API handlers (`auth_handler_test.go`). Run the full test using:

```bash
go test ./... -v
```