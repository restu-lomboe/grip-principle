const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const secretKey = 'testingGrid'; // Replace with your own secret key

// Middleware to parse incoming JSON data
app.use(bodyParser.json());

// MySQL database configuration
const dbConfig = {
  host: 'localhost',
  port: '3307',
  user: 'root',
  password: '',
  database: 'express-testing',
};

// Function to create MySQL connection pool
const createConnectionPool = async () => {
  return await mysql.createPool(dbConfig);
};

// Route to handle user registration
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Create a MySQL connection pool
    const pool = await createConnectionPool();

    // Check if the user already exists in the database
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];

    if (user) {
      return res.status(409).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    await pool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Middleware to authenticate the user using JWT (Bearer Token)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Route to handle user login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Create a MySQL connection pool
    const pool = await createConnectionPool();

    // Retrieve user data from the database
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    // Compare the hashed password from the database with the input password
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    // Create and sign a JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, secretKey, {
      expiresIn: '1h', // Token expires in 1 hour
    });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

//change password
app.post('/api/change-password', authenticateToken, async (req, res) => {
  // Access user information from the decoded token
  const user = req.user;
  const { passwordOld, passwordNew } = req.body;
  let getUser;
  try {
    // Create a MySQL connection pool
    const pool = await createConnectionPool();

    //get user by token jwt
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [user.username]);
    getUser = rows[0];

    //check old password
    const isPasswordMatch = await bcrypt.compare(passwordOld, getUser.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ message: 'Old password does not match' });
    }

    //check old password and new password cannot be same
    if (passwordOld === passwordNew) {
      return res.status(400).json({ message: 'Old password and new password cannot be same' });
    }

    const hashedPassword = await bcrypt.hash(passwordNew, 10);
    // Insert the new user into the database
    await pool.query('UPDATE users set password = ? where username = ?', [hashedPassword, user.username]);

    res.json({ message: 'change password successfully' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error });
  }
});

//create book
app.get('/api/book', authenticateToken, async (req, res) => {
  try {
    const { book } = req.body
    // Create a MySQL connection pool
    const pool = await createConnectionPool();

    const [rows] = await pool.query('SELECT * from books');
    const books = rows;

    res.json(books);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err });
  }
});

//create book
app.post('/api/book/create', authenticateToken, async (req, res) => {
  try {
    const { book } = req.body
    // Create a MySQL connection pool
    const pool = await createConnectionPool();

    // Insert the new user into the database
    await pool.query('INSERT INTO books (book) VALUES (?)', [book]);

    res.json({ message: 'create book successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err });
  }
});

//update book
app.patch('/api/book/:bookId', authenticateToken, async (req, res) => {
  try {
    const { book } = req.body
    // Create a MySQL connection pool
    const pool = await createConnectionPool();

    // Insert the new user into the database
    await pool.query('UPDATE books set book = ? where id = ?', [book, req.params.bookId]);

    res.json({ message: 'update book successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err });
  }
});

//update book
app.delete('/api/book/:bookId', authenticateToken, async (req, res) => {
  try {
    const { book } = req.body
    // Create a MySQL connection pool
    const pool = await createConnectionPool();

    // Insert the new user into the database
    await pool.query('DELETE FROM books where id = ?', [req.params.bookId]);

    res.json({ message: 'delete book successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err });
  }
});

//logout
app.post('/api/logout', authenticateToken, (req, res) => {
  // You may include additional logic here if needed, but for JWT-based logout, simply send a success response.
  res.json({ message: 'Logout successfully' });
});


// Start the server
const port = 8080;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
