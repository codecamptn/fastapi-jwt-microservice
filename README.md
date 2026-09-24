FastAPI JWT Microservice



A secure RESTful API microservice built using FastAPI with JWT authentication, bcrypt password hashing, Pydantic validation, and SQLite database persistence.



Features

User registration

JWT-based login authentication

Password hashing using bcrypt

Bearer token authorization

Protected user profile endpoint

User profile update and deletion

SQLite database persistence

Pydantic request validation

Interactive Swagger/OpenAPI documentation

FastAPI automatic API documentation

Technologies Used

Python

FastAPI

Uvicorn

SQLite

JWT

Passlib

bcrypt

Pydantic

API Endpoints

Method	Endpoint	Description	Authentication

GET	/	API status	No

POST	/register	Register a new user	No

POST	/login	Login and generate JWT	No

GET	/users/me	Get current user	JWT

PUT	/users/me	Update current user	JWT

DELETE	/users/me	Delete current user	JWT

Run Locally



Clone the repository:



git clone https://github.com/codecamptn/fastapi-jwt-microservice.git

cd fastapi-jwt-microservice



Create and activate a virtual environment:



python -m venv venv

venv\\Scripts\\activate



Install dependencies:



pip install -r requirements.txt



Start the server:



uvicorn main:app --reload

Swagger Documentation



Open:



http://127.0.0.1:8000/docs



Swagger provides interactive documentation and allows testing all API endpoints.



Authentication Flow

Register a user using /register.

Login using /login.

Receive a JWT access token.

Authorize Swagger using the JWT credentials.

Access protected endpoints such as /users/me.

Update or delete the authenticated user's profile.

Database



The application uses SQLite for local persistence.



The database file is intentionally excluded from Git using .gitignore.



Security

Passwords are stored as bcrypt hashes rather than plain text.

Protected endpoints require JWT authentication.

Request data is validated using Pydantic.

JWT tokens have an expiration time.

Database files and virtual-environment files are excluded from version control.

Project Structure

fastapi-jwt-microservice/

│

├── main.py

├── requirements.txt

├── .gitignore

└── README.md

Repository



https://github.com/codecamptn/fastapi-jwt-microservice

