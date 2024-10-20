const dotenv = require('dotenv')
dotenv.config();
const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');

const app = express();
const port =  process.env.PORT || 3000;

// MongoDB Connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

if (!uri) {
  console.error("MongoDB URI not found in environment variables");
  process.exit(1);
}

// MongoDB Client
let db;

// Function to connect to the database (reused across requests)
const connectToDb = async () => {
  if (db) {
      // Reuse existing database connection
      return db;
  }
  try {
      await client.connect();
      db = client.db("PassHaven");
      console.log("Connected to MongoDB");
      return db;
  } catch (err) {
      console.error("Database connection error:", err);
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
// app.listen(port, () => {
//   console.log(`PassHaven backend listening on port ${port}`);
// });

module.exports = app