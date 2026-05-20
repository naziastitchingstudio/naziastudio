const jwt = require('jsonwebtoken');
const { serialize } = require('cookie');
const { getCollection } = require('../db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { phone, code, token, isFirebase } = req.body;
    
    if (!phone) {
      return res.status(400).json({ error: 'Missing phone' });
    }

    if (!isFirebase && !code) {
      return res.status(400).json({ error: 'Missing verification code' });
    }

    // In a production environment with Firebase Admin, you would verify the 'token' here.
    // For this client-side demo, we trust the isFirebase flag.
    
    const collection = await getCollection('users');
    if (!collection) return res.status(500).json({ error: 'Database configuration missing' });

    let userRow = await collection.findOne({ Phone: phone });
    
    if (!userRow) {
      // User doesn't exist, create a new user account seamlessly
      const newUser = {
        ID: Date.now().toString(),
        CreatedAt: new Date().toISOString(),
        Name: "User " + phone.substring(phone.length - 4),
        Email: phone.replace(/[^0-9]/g, '') + "@whatsapp.user", // placeholder
        Phone: phone,
        PasswordHash: "", // No password for WhatsApp-only users initially
        Address: '',
        Measurements: ''
      };
      await collection.insertOne(newUser);
      userRow = newUser;
    }

    // Generate JWT
    const jwtToken = jwt.sign(
      { id: userRow.ID, name: userRow.Name, email: userRow.Email, phone: userRow.Phone },
      process.env.JWT_SECRET || 'dev-secret-key-do-not-use-in-prod',
      { expiresIn: '7d' }
    );

    // Set secure HTTP-Only cookie
    res.setHeader('Set-Cookie', serialize('auth_token', jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24 * 7, // 7 days
      path: '/'
    }));

    res.status(200).json({ 
      success: true, 
      user: { name: userRow.Name, email: userRow.Email, phone: userRow.Phone }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database Error: ' + err.message });
  }
};
