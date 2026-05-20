const bcrypt = require('bcryptjs');
const { getCollection } = require('../db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const collection = await getCollection('users');
    if (!collection) return res.status(500).json({ error: 'Database configuration missing' });

    // Check if user exists
    const existingUser = await collection.findOne({ Email: email });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const newUser = {
      ID: Date.now().toString(),
      CreatedAt: new Date().toISOString(),
      Name: name,
      Email: email,
      Phone: phone || '',
      PasswordHash: passwordHash,
      Address: '',
      Measurements: ''
    };

    await collection.insertOne(newUser);

    res.status(201).json({ success: true, message: 'Registration successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database Error: ' + err.message });
  }
};
