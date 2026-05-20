const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { serialize } = require('cookie');
const { getCollection } = require('../db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { email, password } = req.body;
    // The "email" field might contain either an email address or a phone number.
    if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });

    const collection = await getCollection('users');
    if (!collection) return res.status(500).json({ error: 'Database configuration missing' });

    const userRow = await collection.findOne({
      $or: [
        { Email: email },
        { Phone: email } // treat the input as potentially a phone number
      ]
    });
    
    if (!userRow) return res.status(401).json({ error: 'NOT_FOUND' });

    const isMatch = await bcrypt.compare(password, userRow.PasswordHash);
    if (!isMatch) return res.status(401).json({ error: 'WRONG_PASSWORD' });

    // Generate JWT
    const token = jwt.sign(
      { id: userRow.ID, name: userRow.Name, email: userRow.Email, phone: userRow.Phone },
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

    // If the user doesn't have isVerified explicitly set, assume true if they have an email, else false
    const isVerified = userRow.isVerified !== undefined ? userRow.isVerified : (userRow.Email ? true : false);

    res.status(200).json({ 
      success: true, 
      user: { name: userRow.Name, email: userRow.Email, phone: userRow.Phone, isVerified: isVerified }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database Error: ' + err.message });
  }
};
