
require('dotenv').config();
const express = require('express');
var cors = require('cors');
const mysql = require('mysql');
var SHA1  = require('sha1');

const app = express();
const port = process.env.APP_PORT;

const pwdRegExp = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/
 
var pool = mysql.createPool({
  connectionLimit: process.env.DB_CONNLIMIT,
  multipleStatements: process.env.DB_MULTI_QUERY,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  timezone:process.env.DB_TIMEZONE
});
app.use(cors());
app.use(express.urlencoded({ extended: true })); // ez kell, hogy a req.body mukodjon
app.use(express.json());

app.get('/', (req, res) => {
    res.send('Welcome to the Weather Forecast API!');
});

//USER ENDPOINTS -------------------

//register user
app.post('/register', (req, res) => {
    const { username, passwd, email, confirm} = req.body;
    if (!username || !passwd || !email || !confirm) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (passwd != confirm) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }
/*
    if (!pwdRegExp.test(passwd)) {
        return res.status(400).json({ error: 'Password does not meet requirements' });
    }
*/
    pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length > 0) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        pool.query('INSERT INTO users (name, passwd, email) VALUES (?, ?, ?)', [username, SHA1(passwd), email], (err, results) => {
            if (err) {
                return res.status(500).json({error});
            }
            if (results.affectedRows > 0) {
                return res.status(201).json({ message: 'User registered successfully' });
            }
        })
    })
})

//login
app.post('/login', (req, res) => {
    const { email, passwd } = req.body;
    if (!email || !passwd) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE email = ? AND passwd = ?', [email, SHA1(passwd)], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        if (results.length > 0) {
            return res.status(200).json({ message: 'Login successful', user: results[0] });
        }
    })
})

//get user data
app.get('/profile/:luid', (req, res) => {
    const { luid } = req.params;
    pool.query('SELECT * FROM users WHERE id = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            return res.status(200).json({ user: results[0] });
        })
    })
})

//passmod

// modify prifile data




























/**
 * Weather app
 * 
 * USERS:
 * ------------
 * 
 * HOME PAGE
 * 
 * POST register
 * 
 * POST login
 */


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});