# Reachify Full Stack Assignment

## Overview

The **Reachify Full Stack Assignment** is a web application designed to manage todo tasks efficiently. This project showcases a full-stack implementation using **FastAPI** for the backend and **React** with **Chakra UI** for the frontend. The application allows users to register, log in, and manage their todo items seamlessly.

### Live Demo

You can view the live demo of the application at: [Live Demo on Vercel](https://j-gaurav-varma-reachify-full-stack-assignment-frontend.vercel.app/)

## Project Structure

The project consists of two main components:

1. **Backend**: Built with FastAPI, it handles user authentication and todo management.
2. **Frontend**: Developed using React, it provides a user-friendly interface for interacting with the backend.

### Backend Repository

- **GitHub Repository**: [Backend Repository](https://github.com/GauravOOO2/J-Gaurav-Varma---Reachify-Full-Stack-Assignment-Backend.git)
- **Docker Pull Command**: 
  ```bash
  docker pull gaurav254/j-gaurav-varma-reachify-full-stack-assignment:backend
  ```

### Frontend Repository

- **GitHub Repository**: [Frontend Repository](https://github.com/GauravOOO2/J-Gaurav-Varma---Reachify-Full-Stack-Assignment-Frontend.git)
- **Docker Pull Command**: 
  ```bash
  docker pull gaurav254/j-gaurav-varma-reachify-full-stack-assignment:frontend
  ```

## Features

### Backend Features

- **User Registration**: Users can create an account with a unique username and password.
- **User Authentication**: Secure login functionality using JWT tokens.
- **Todo Management**: Users can create, read, update, and delete their todo items.
- **MongoDB Integration**: Utilizes MongoDB for data storage, ensuring persistence of user data and todos.

### Frontend Features

- **Responsive Design**: Built with Chakra UI for a modern and responsive user interface.
- **User-Friendly Interface**: Easy navigation for users to manage their todos.
- **Real-Time Updates**: Automatically updates the todo list without needing to refresh the page.
- **Error Handling**: Provides user feedback for successful actions and error states.

## Technologies Used

- **Backend**: 
  - FastAPI
  - MongoDB
  - Python
  - JWT for authentication
- **Frontend**: 
  - React
  - Chakra UI
  - Axios for API calls
  - Vercel for deployment

## Getting Started

### Prerequisites

- Docker installed on your machine.
- Node.js and npm (for frontend development).
- Python 3.9 or higher (for backend development).

### Running the Backend

1. Clone the backend repository:
   ```bash
   git clone https://github.com/GauravOOO2/J-Gaurav-Varma---Reachify-Full-Stack-Assignment-Backend.git
   cd J-Gaurav-Varma---Reachify-Full-Stack-Assignment-Backend
   ```

2. Run the backend with:
    ```bash
    uvicorn main:app --reload
     ```
    Access the frontend application at `http://localhost:3000`.

   OR

3. Pull and Run the Docker Image:
   ```bash
   docker pull gaurav254/j-gaurav-varma-reachify-full-stack-assignment:backend
   ```



### Running the Frontend

1. Clone the frontend repository:
   ```bash
   git clone https://github.com/GauravOOO2/J-Gaurav-Varma---Reachify-Full-Stack-Assignment-Frontend.git
   cd J-Gaurav-Varma---Reachify-Full-Stack-Assignment-Frontend
   ```

2. Run the frontend with:
    ```bash
    npm start
     ```
    Access the frontend application at `http://localhost:3000`.


    OR
3. Pull and Run the Docker Image:
   ```bash
   docker pull gaurav254/j-gaurav-varma-reachify-full-stack-assignment:frontend
   ```



3. Access the frontend application at `http://localhost:3000`.

## Contributing

Contributions are welcome! If you have suggestions for improvements or features, feel free to open an issue or submit a pull request.


## Acknowledgments

- Thanks to the FastAPI and React communities for their excellent documentation and support.
- Special thanks to Vercel for providing a platform for easy deployment.

---

Feel free to reach out if you have any questions or need further assistance!
