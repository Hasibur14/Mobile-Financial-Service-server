const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${encodeURIComponent(process.env.DB_PASSWORD)}@cluster0.lfxjcnl.mongodb.net/mfs?retryWrites=true&w=majority`;

// Create a MongoClient
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

async function connectToDatabase() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');

    const db = client.db('mfs');
    const userCollection = db.collection('user');
    const adminCollection = db.collection('admin');
    const agentCollection = db.collection('agent');

    // JWT generation endpoint
    app.post('/jwt', (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '24h' });
      res.send({ token });
    });

    // Middleware to verify token
    const verifyToken = (req, res, next) => {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).send({ message: 'Unauthorized access' });
      }
      const token = authHeader.split(' ')[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: 'Unauthorized access' });
        }
        req.decoded = decoded;
        next();
      });
    };

    // Registration Route
    app.post('/register', async (req, res) => {
      const { name, pin, mobileNumber, email } = req.body;

      try {
        // Hash the PIN
        const salt = await bcrypt.genSalt(10);
        const hashedPin = await bcrypt.hash(pin, salt);

        // Create new user
        const newUser = { name, pin: hashedPin, mobileNumber, email };

        // Save user to the database
        const result = await userCollection.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: 'Server error' });
      }
    });

    // Login Route
    app.post('/login', async (req, res) => {
      const { mobileNumber, pin } = req.body;

      try {
        // Find user by mobile number
        const user = await userCollection.findOne({ mobileNumber });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        // Check PIN
        const isMatch = await bcrypt.compare(pin, user.pin);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Generate JWT
        const payload = { id: user._id, name: user.name };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '12h' });

        res.json({ token });
      } catch (error) {
        res.status(500).json({ error: 'Server error' });
      }
    });

    // Root Route
    app.get('/', (req, res) => {
      res.send('MFS Application is running');
    });

    // Start Server
    app.listen(port, () => {
      console.log(`MFS Application is running on port: ${port}`);
    });

  } catch (error) {
    console.error('Failed to connect to MongoDB', error);
    process.exit(1);
  }
}

connectToDatabase().catch(console.dir);
