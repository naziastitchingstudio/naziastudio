const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { serialize } = require('cookie');
const { getCollection } = require('../db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });

    const collection = await getCollection('users');
    if (!collection) return res.status(500).json({ error: 'Database configuration missing' });

    const userRow = await collection.findOne({ Email: email });
    
    if (!userRow) return res.status(401).json({ error: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, userRow.PasswordHash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid email or password' });

    // Generate JWT
    const token = jwt.sign(
      { id: userRow.ID, name: userRow.Name, email: userRow.Email },
      process.env.JWT_SECRET || 'dev-secret-key-do-not-use-in-prod',
      { expiresIn: '7d' }
    );

    // Set secure HTTP-Only cookie
    res.setHeader('Set-Cookie', serialize('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7, // 7 days
      path: '/'
    }));

    res.status(200).json({ 
      success: true, 
      user: { name: userRow.Name, email: userRow.Email }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database Error: ' + err.message });
  }
};
