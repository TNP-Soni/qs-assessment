const express = require('express');
var mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;
const bcrypt = require('bcrypt');

app.use(express.json());

var con = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "password", 
    database: "grocery"
});
const cors = require('cors');
app.use(cors({
    origin: 'http://localhost:4200'
}));

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send({ error: 'Unauthorized: No token provided' });

    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) {
            return res.status(403).send({ error: 'Forbidden: Invalid token' });
        }
        req.user = user;
        next();
    });
}

function isAdmin(req, res, next) {
    if (req.user && req.user.isAdmin) {
        next();
    } else {
        res.status(403).send({ error: 'Forbidden: Admins only' });
    }
}

app.get('/get-items', authenticateToken, (req, res) => {
    con.query('SELECT * FROM items', (err, results) => {
        if (err) {
            res.status(500).send({ error: 'Database query failed' });
        } else {
            res.send(results);
        }
    });
});

app.post('/add-item', authenticateToken, isAdmin, (req, res) => {
    const { name, price, description, quantity } = req.body;
    if (!name || !price || !description || !quantity) {
        return res.status(400).send({ error: 'Name, price, description, and quantity are required' });
    }
    con.query('INSERT INTO items (name, price, description, quantity) VALUES (?, ?, ?, ?)', [name, price, description, quantity], (err, results) => {
        if (err) {
            res.status(500).send({ error: 'Database query failed' });
        } else {
            res.send({ message: 'Item added successfully', id: results.insertId });
        }
    });
});

app.post('/update-item', authenticateToken, isAdmin, (req, res) => {
    const { id, name, price, description, quantity } = req.body;
    if (!id || !name || !price || !description || !quantity) {
        return res.status(400).send({ error: 'ID, name, price, description, and quantity are required' });
    }
    con.query('UPDATE items SET name = ?, price = ?, description = ?, quantity = ? WHERE id = ?', [name, price, description, quantity, id], (err, results) => {
        if (err) {
            res.status(500).send({ error: 'Database query failed' });
        } else {
            res.send({ message: 'Item updated successfully' });
        }
    });
});

app.post('/delete-item', authenticateToken, isAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) {
        return res.status(400).send({ error: 'ID is required' });
    }
    con.query('DELETE FROM items WHERE id = ?', [id], (err, results) => {
        if (err) {
            res.status(500).send({ error: 'Database query failed' });
        } else {
            res.send({ message: 'Item deleted successfully' });
        }
    });
});

app.post('/book-items', authenticateToken, (req, res) => {
    const { items } = req.body;
    if (!items || !Array.isArray(items) || items.length === 0) {
        return res.status(400).send({ error: 'Items are required and should be an array' });
    }

    const values = items.map(item => [req.user.id, item.id, item.quantity]);

    con.beginTransaction(err => {
        if (err) {
            return res.status(500).send({ error: 'Database transaction failed' });
        }

        con.query('INSERT INTO bookings (user_id, item_id, quantity) VALUES ?', [values], (err, results) => {
            if (err) {
                return con.rollback(() => {
                    res.status(500).send({ error: 'Database query failed' });
                });
            }

            const updateQueries = items.map(item => {
                return new Promise((resolve, reject) => {
                    con.query('UPDATE items SET quantity = quantity - ? WHERE id = ?', [item.quantity, item.id], (err, results) => {
                        if (err) {
                            return reject(err);
                        }
                        resolve(results);
                    });
                });
            });

            Promise.all(updateQueries)
                .then(() => {
                    con.commit(err => {
                        if (err) {
                            return con.rollback(() => {
                                res.status(500).send({ error: 'Database commit failed' });
                            });
                        }
                        res.send({ message: 'Items booked and quantities updated successfully' });
                    });
                })
                .catch(err => {
                    con.rollback(() => {
                        res.status(500).send({ error: 'Database query failed' });
                    });
                });
        });
    });
});

app.post('/update-item-quantity', authenticateToken, isAdmin, (req, res) => {
    const { id, quantity } = req.body;
    if (!id || !quantity) {
        return res.status(400).send({ error: 'ID and quantity are required' });
    }
    con.query('UPDATE items SET quantity = ? WHERE id = ?', [quantity, id], (err, results) => {
        if (err) {
            res.status(500).send({ error: 'Database query failed' });
        } else {
            res.send({ message: 'Item quantity updated successfully' });
        }
    });
});

app.post('/register', async (req, res) => {
    const { firstName, lastName, email, password, isAdmin } = req.body;
    if (!firstName || !lastName || !email || !password) {
        return res.status(400).send({ error: 'First name, last name, email, and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    con.query('INSERT INTO users (firstName, lastName, email, password, isAdmin) VALUES (?, ?, ?, ?, ?)', [firstName, lastName, email, hashedPassword, isAdmin], (err, results) => {
        if (err) {
            res.status(500).send({ error: 'Database query failed' });
        } else {
            const token = jwt.sign({ id: results.insertId, isAdmin }, 'your_jwt_secret', { expiresIn: '1h' });
            res.send({ message: 'User registered successfully', id: results.insertId, token, isAdmin });
        }
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send({ error: 'Email and password are required' });
    }

    con.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            return res.status(500).send({ error: 'Database query failed' });
        }

        if (results.length === 0) {
            return res.status(400).send({ error: 'Invalid email or password' });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(400).send({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, 'your_jwt_secret', { expiresIn: '1h' });
        res.send({ message: 'Login successful', token, isAdmin: user.isAdmin });
    });
});

app.listen(port, () => {
    console.log(`Grocery app listening at http://localhost:${port}`);
});