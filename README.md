
### README.md:
```markdown
# Data Integrity API with Two-Factor Authentication

A Flask-based REST API that implements secure authentication with 2FA and provides product management functionality.

## Features

- **User Authentication**:
  - Secure signup with password hashing
  - Login with username/password
  - Two-factor authentication using TOTP (Time-based One-Time Password)
  - QR code generation for 2FA setup

- **Product Management**:
  - Create, read, update, and delete products
  - JWT-protected endpoints
  - Product fields: name, description, price, stock

## Technologies Used

- Python 3
- Flask
- PyMongo (MongoDB)
- Flask-Bcrypt (password hashing)
- Flask-JWT-Extended (token authentication)
- PyOTP (2FA implementation)
- QRCode (QR generation)

## Installation

1. Clone the repository
2. Install requirements:
   ```
   pip install flask flask-pymongo flask-bcrypt flask-jwt-extended pyotp qrcode
   ```
3. Ensure MongoDB is running locally on port 27017
4. Run the application:
   ```
   python data_integrity_api.py
   ```

## API Endpoints

### Authentication
- `POST /signup` - Register a new user
- `POST /login` - Login with credentials
- `POST /verify-2fa` - Verify 2FA code
- `GET /generate-2fa/<username>` - Get QR code for 2FA setup

### Products
- `POST /products` - Create new product (JWT required)
- `GET /products` - List all products (JWT required)
- `GET /products/<pid>` - Get single product (JWT required)
- `PUT /products/<pid>` - Update product (JWT required)
- `DELETE /products/<pid>` - Delete product (JWT required)

## Security Notes

- All passwords are hashed with bcrypt
- JWT tokens expire after 10 minutes
- 2FA is required for all authenticated operations
- Never share your JWT_SECRET_KEY in production

## License

MIT License
```

This README provides:
1. Clear overview of the system
2. Installation instructions
3. API documentation
4. Security information
5. Technology stack details

The file name `data_integrity_api.py` emphasizes both the security (2FA) and data management aspects of your application.
