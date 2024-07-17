const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');
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
        // Check if user already exists
        const existingUser = await userCollection.findOne({
          $or: [{ mobileNumber }, { email }]
        });
        if (existingUser) {
          return res.status(400).json({ error: 'User already exists' });
        }

        // Hash the PIN
        const salt = await bcrypt.genSalt(10);
        const hashedPin = await bcrypt.hash(pin, salt);

        // Create new user
        const newUser = {
          name,
          pin: hashedPin,
          mobileNumber,
          email,
          role: 'user',
          status: 'active'
        };

        // Save user to the database
        const result = await userCollection.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
      } catch (error) {
        res.status(500).json({ error: 'Server error' });
      }
    });

    // Login Route
    app.post('/login', async (req, res) => {
      const { identifier, pin } = req.body; // `identifier` can be either mobileNumber or email

      try {
        // Find user by mobile number or email
        const user = await userCollection.findOne({
          $or: [{ mobileNumber: identifier }, { email: identifier }]
        });
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        // Check PIN
        const isMatch = await bcrypt.compare(pin, user.pin);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Generate JWT
        const payload = { id: user._id, name: user.name, role: user.role };
        const token = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '12h' });

        res.json({ token });
      } catch (error) {
        res.status(500).json({ error: 'Server error' });
      }
    });

    // Get all users with a specific role
    app.get('/users/:role', async (req, res) => {
      const role = req.params.role;
      const users = await userCollection.find({ role }).toArray();
      res.send(users);
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
