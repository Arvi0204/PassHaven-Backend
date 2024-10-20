const dotenv = require('dotenv')
dotenv.config();
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');

const app = express();
const port = 2000;

// MongoDB Connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

const connectToDb = async () => {
  try {
    await client.connect();

    const db = client.db("PassHaven");
    return db;
  } catch (err) {
    console.log("Database connection error:", err);
    throw err;
  }
};

// Export the function so it can be used in other modules
module.exports = connectToDb;

// Middleware
app.use(cors());
app.use(express.json());

// Available routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/passwords', require('./routes/passwords'));

// Root endpoint
app.get('/', (req, res) => {
  res.send('Hello from PassHaven!');
});

// Server listening
app.listen(port, () => {
  console.log(`PassHaven backend listening on port ${port}`);
});

module.exports = server;