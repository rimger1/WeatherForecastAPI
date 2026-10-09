
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

//get profile
app.get('/profile/:luid', (req, res) => {
    const { luid } = req.params;
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0) {
            return res.status(200).json({results});
        }
    })
})

//passmod
app.patch('/passmod/:luid', (req, res) => {
    const luid  = req.params.luid;
    const {oldPasswd, newPasswd, confirm} = req.body;
    if (!oldPasswd || !newPasswd || !confirm) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (newPasswd != confirm) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }
/*     
    if (!pwdRegExp.test(newPasswd)) {
        return res.status(400).json({ error: 'Password does not meet requirements' });
    }
*/   
 pool.query('SELECT passwd FROM users WHERE ID = ? AND passwd = ?', [luid, SHA1(oldPasswd)], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid old password' });
        }
        if (results.length > 0 && SHA1(newPasswd) === results[0].passwd) {
            return res.status(400).json({ error: 'New password cannot be the same as the old password' });
        }
        pool.query('UPDATE users SET passwd = ? WHERE ID = ?', [SHA1(newPasswd), luid], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'Password updated successfully' });
            }
        })
    })
})


// patch aprofile
app.patch('/profile/:luid', (req, res) => {
    const luid  = req.params.luid;
    const {username, email} = req.body;
    if (!username || !email) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        pool.query('UPDATE users SET name = ?, email = ? WHERE ID = ?', [username, email, luid], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'Profile updated successfully' });
            }
        })
    })
})



//ADMIN ENDPOINTS -------------------

// get users
app.post('/users', (req, res) => {
    const luid = req.body.luid;
    if (!luid) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('SELECT * FROM users', (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            return res.status(200).json({results});
        })
    })
})

// post weather
app.post('/weather', (req, res) => {
    const luid = req.body.luid;
    const { date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index } = req.body;
    if (!luid || !date || !location || !temp_min || !temp_max || !weather_type || !precipitation || !precipitation_probability || !wind_speed || !wind_direction || !humidity || !pressure || !uv_index){
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (temp_min > temp_max) {
        return res.status(400).json({ error: 'Minimum temperature cannot be greater than maximum temperature' });
    }
    if (precipitation_probability < 0 || precipitation_probability > 100) {
        return res.status(400).json({ error: 'Precipitation probability must be between 0 and 100' });
    }
    if (uv_index < 0 || uv_index > 11) {
        return res.status(400).json({ error: 'UV index must be between 0 and 11' });
    }
    if (humidity < 0 || humidity > 100) {
        return res.status(400).json({ error: 'Humidity must be between 0 and 100' });
    }
    if (pressure < 0) {
        return res.status(400).json({ error: 'Pressure must be greater than 0' }); 
    }
    if (wind_speed < 0) {
        return res.status(400).json({ error: 'Wind speed must be greater than 0' });
    }
    if (precipitation < 0) {
        return res.status(400).json({ error: 'Precipitation must be greater than 0' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ err});
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('INSERT INTO weather (date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index], (err, results) => {
            if (err) {
                return res.status(500).json({ err});
            }
            if (results.affectedRows > 0) {
                return res.status(201).json({ message: 'Weather data added successfully' });
            }
        })
    })
})


// patch weather
app.patch('/weather/:id', (req, res) => {
    const luid = req.body.luid;
    const id = req.params.id;
    const { date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index } = req.body;
    if (!luid || !date || !location || !temp_min || !temp_max || !weather_type || !precipitation || !precipitation_probability || !wind_speed || !wind_direction || !humidity || !pressure || !uv_index){
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (temp_min > temp_max) {
        return res.status(400).json({ error: 'Minimum temperature cannot be greater than maximum temperature' });
    }
    if (precipitation_probability < 0 || precipitation_probability > 100) {
        return res.status(400).json({ error: 'Precipitation probability must be between 0 and 100' });
    }
    if (uv_index < 0 || uv_index > 11) {
        return res.status(400).json({ error: 'UV index must be between 0 and 11' });
    }
    if (humidity < 0 || humidity > 100) {
        return res.status(400).json({ error: 'Humidity must be between 0 and 100' });
    }
    if (pressure < 0) {
        return res.status(400).json({ error: 'Pressure must be greater than 0' });
    }
    if (wind_speed < 0) {
        return res.status(400).json({ error: 'Wind speed must be greater than 0' });
    }
    if (precipitation < 0) {
        return res.status(400).json({ error: 'Precipitation must be greater than 0' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('UPDATE weather SET date = ?, location = ?, temp_min = ?, temp_max = ?, weather_type = ?, precipitation = ?, precipitation_probability = ?, wind_speed = ?, wind_direction = ?, humidity = ?, pressure = ?, uv_index = ? WHERE ID = ?', [date, location, temp_min,temp_max,weather_type,precipitation,precipitation_probability,wind_speed,wind_direction,humidity,pressure,uv_index, id], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'Weather data updated successfully' });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'Weather data not found' });
            }
        })
    })
})

// delete weather
app.delete('/weather/:id', (req, res) => {
    const luid = req.body.luid;
    const id = req.params.id;
    if (!luid) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!id) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }   
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('DELETE FROM weather WHERE ID = ?', [id], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'Weather data deleted successfully' });
            }
            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'Weather data not found' });
            }
        })
    })
})

// deny user
app.patch('/deny/:id', (req, res) => {
    const luid = req.body.luid;
    const id = req.params.id;
    if (!luid) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    if (!id) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    pool.query('SELECT * FROM users WHERE ID = ?', [luid], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (results.length > 0 && results[0].role !== 'admin') {
            return res.status(403).json({ error: 'Access denied' });
        }
        pool.query('UPDATE users SET status = not status WHERE ID = ?', [id], (err, results) => {
            if (err) {
                return res.status(500).json({ err});
            }
            if (results.affectedRows > 0) {
                return res.status(200).json({ message: 'User denied successfully' });
            }
            if (results.affectedRows === 0){
                return res.status(404).json({ error: 'User not found' });
            }
        })
    })
})





// WEATHER ENDPOINTS -------------------

//get weather
app.get('/weather', (req, res) => {
    pool.query('SELECT * FROM weather', (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'No weather data found' });
        }
        if (results.length > 0) {
            return res.status(200).json({results});
        }
    })
})

//get weather details
app.get('/weather/:id', (req, res) => {
    const id = req.params.id;
    pool.query('SELECT * FROM weather WHERE ID = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'Weather data not found' });
        }
        if (results.length > 0) {
            return res.status(200).json({results});
        }
    })
})




















/**
 * Weather app
 * 
 * GUEST ENDPOINTS:
 * -----------------------------
 * HOME PAGE
 * 
 * GET weather 
 * 
 * POST register pipa
 * 
 * POST login pipa
 * 
 * 
 * USERS ENDPOINTS:
 * -----------------------------
 * GET profile pipa
 * 
 * PATCH profile pipa
 * 
 * PATCH passmod pipa
 * 
 * GET weather details
 * 
 * 
 * ADMIN ENDPOINTS:
 * -----------------------------
 * GET users pipa
 * 
 * POST weather pipa
 * 
 * PATCH weather pipa
 * 
 * DELETE weather pipa
 * 
 * DENY user
 */


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});