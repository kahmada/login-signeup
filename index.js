const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const pool = require('./db');
require('dotenv').config();

const app = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
    );

    res.send(' Compte créé avec succès !');
  } catch (err) {
    console.error('Erreur lors de l\'inscription :', err);
    res.status(500).send(' Erreur serveur');
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).send('<h2> Identifiant ou mot de passe incorrect.</h2>');
    }

    const user = result.rows[0];

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      res.send('<h2> Connexion réussie !</h2>');
    } else {
      res.status(400).send('<h2> Identifiant ou mot de passe incorrect.</h2>');
    }
  } catch (err) {
    console.error(' Erreur SQL :', err);
    res.status(500).send('Erreur serveur.');
  }
});
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );
    `);
    console.log('✅ Table "users" vérifiée/créée');
  } catch (err) {
    console.error('Erreur création de la table "users" :', err);
  }
})();

app.listen(PORT, () => {
  console.log(` Serveur lance sur http://localhost:${PORT}`);
});
