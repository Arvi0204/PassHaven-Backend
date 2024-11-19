# PassHaven - Backend

This is the backend repository of PassHaven, a password manager app that prioritizes security and performance. The backend handles user authentication, encrypted storage of passwords, and API operations for the frontend and Chrome extension.

---

## Features

- **Secure Authentication**: JSON Web Token (JWT)-based user login validation.
- **Encrypted Data Storage**: Passwords are encrypted using AES-256 before storage.
- **Comprehensive APIs**: CRUD operations for password management.
- **MongoDB Integration**: Data is securely stored and fetched from a MongoDB database.
- **Express Framework**: Lightweight and performant backend framework.

---

## Tech Stack

- **Node.js**: Backend runtime environment.
- **Express.js**: Web framework for building REST APIs.
- **MongoDB**: NoSQL database for secure data storage.
- **AES-256 Encryption**: Ensures all sensitive data is securely encrypted.
- **CORS**: Enabled for secure communication with the frontend.

---

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/Arvi0204/passhaven-backend.git
cd passhaven-backend
```

### 2. Install dependencies
```bash
npm install
```

### 3. Configure environment variables
Create a `.env` file in the root directory with the following keys:
```env
MONGODB_URI=your-mongodb-uri
JWT_SECRET=your-jwt-
ENCRYPTION_SECRET=your-aes-256-encryption-secret
PORT=8000
```

### 4. Run the server
```bash
npm start
```

### 5. Test the APIs
Use tools like **Postman** or **ThunderClient** to test the endpoints.

---

## API Endpoints

### Authentication
- `POST /auth/createuser`: Register a new user.
- `POST /auth/login`: Authenticate user and return a JWT.
- `POST /auth/getuser`: Retrieve an existing user account details.
- `POST /auth/changepassword`: Change an existing user account password.
- `POST /auth/deleteuser`: Delete an existing user account.

### Password Management
- `GET /fetchallpass`: Retrieve all passwords for the authenticated user.
- `POST /addpass`: Create a new password entry.
- `PUT /updatepass/:id`: Update an existing password entry.
- `DELETE /deletepass/:id`: Delete a password entry.
- `DELETE /deleteallpass`: Delete all password entries.

---

## Deployment

The backend is hosted on **Vercel**.

**Live API URL**: [PassHaven Backend](https://pass-haven-backend.vercel.app)

---

## Folder Structure

- **/routes**: Contains route handlers for authentication and password management.
- **/utils**: Helper functions like encryption and token validation.
- **/middlewares**: Express middlewares used to validate user authentication, JWT token verification, and request body parsing.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.