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
    // Connect to MongoDB
    await client.connect();
    console.log('Connected to MongoDB');

    const db = client.db('mfs');
    const usersCollection = db.collection('users');
    const agentsCollection = db.collection('agents');

    // Helper function for JWT authentication
    const authenticate = (req, res, next) => {
      const token = req.header('Authorization');
      if (!token) return res.status(401).json({ error: 'No token, authorization denied' });

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
      } catch (error) {
        res.status(400).json({ error: 'Token is not valid' });
      }
    };

    // Routes
    app.post('/api/users/register', async (req, res) => {
      try {
        const { name, pin, mobileNumber, email } = req.body;
        const hashedPin = await bcrypt.hash(pin, 10);
        const newUser = {
          name,
          pin: hashedPin,
          mobileNumber,
          email,
          status: 'pending',
          balance: 0,
        };
        await usersCollection.insertOne(newUser);
        res.status(201).json({ message: 'User registered successfully!' });
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.post('/api/users/login', async (req, res) => {
      try {
        const { identifier, pin } = req.body;
        const user = await usersCollection.findOne({
          $or: [{ mobileNumber: identifier }, { email: identifier }]
        });
        if (!user) return res.status(400).json({ error: 'User not found!' });

        const isMatch = await bcrypt.compare(pin, user.pin);
        if (!isMatch) return res.status(400).json({ error: 'Invalid PIN!' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.get('/api/users/balance', authenticate, async (req, res) => {
      try {
        const user = await usersCollection.findOne({ _id: ObjectId(req.user.id) });
        res.status(200).json({ balance: user.balance });
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.post('/api/agents/register', async (req, res) => {
      try {
        const { name, pin, mobileNumber, email } = req.body;
        const hashedPin = await bcrypt.hash(pin, 10);
        const newAgent = {
          name,
          pin: hashedPin,
          mobileNumber,
          email,
          status: 'pending',
          balance: 0,
        };
        await agentsCollection.insertOne(newAgent);
        res.status(201).json({ message: 'Agent registered successfully!' });
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.post('/api/agents/login', async (req, res) => {
      try {
        const { identifier, pin } = req.body;
        const agent = await agentsCollection.findOne({
          $or: [{ mobileNumber: identifier }, { email: identifier }]
        });
        if (!agent) return res.status(400).json({ error: 'Agent not found!' });

        const isMatch = await bcrypt.compare(pin, agent.pin);
        if (!isMatch) return res.status(400).json({ error: 'Invalid PIN!' });

        const token = jwt.sign({ id: agent._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.get('/api/agents/balance', authenticate, async (req, res) => {
      try {
        const agent = await agentsCollection.findOne({ _id: ObjectId(req.user.id) });
        res.status(200).json({ balance: agent.balance });
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.post('/api/admin/login', async (req, res) => {
      try {
        const { identifier, pin } = req.body;
        const admin = await db.collection('admins').findOne({
          $or: [{ mobileNumber: identifier }, { email: identifier }]
        });
        if (!admin) return res.status(400).json({ error: 'Admin not found!' });

        const isMatch = await bcrypt.compare(pin, admin.pin);
        if (!isMatch) return res.status(400).json({ error: 'Invalid PIN!' });

        const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.get('/api/admin/users', authenticate, async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        res.status(200).json(users);
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    app.get('/api/admin/agents', authenticate, async (req, res) => {
      try {
        const agents = await agentsCollection.find().toArray();
        res.status(200).json(agents);
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
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
