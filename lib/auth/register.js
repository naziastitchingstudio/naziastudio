const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { serialize } = require('cookie');
const { getCollection } = require('../db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { name, email, phone, password, otp } = req.body;
    
    if (!name || (!email && !phone) || !password) {
      return res.status(400).json({ error: 'Name, Password, and either Email or Phone are required' });
    }

    const collection = await getCollection('users');
    if (!collection) return res.status(500).json({ error: 'Database configuration missing' });

    // Check if user exists
    if (email) {
      const existingEmail = await collection.findOne({ Email: email });
      if (existingEmail) return res.status(400).json({ error: 'ALREADY_EXISTS' });
    }
    
    if (phone) {
      const existingPhone = await collection.findOne({ Phone: phone });
      if (existingPhone) return res.status(400).json({ error: 'ALREADY_EXISTS' });
    }

    // If Email Registration, an OTP MUST be provided and verified
    if (email) {
      if (!otp) {
        return res.status(400).json({ error: 'OTP is required for email registration.' });
      }

      const otpsCollection = await getCollection('otps');
      const validOtp = await otpsCollection.findOne({ account: email, otp: otp });

      if (!validOtp) {
        return res.status(400).json({ error: 'Invalid verification code!' });
      }

      if (new Date() > new Date(validOtp.expiresAt)) {
        return res.status(400).json({ error: 'Session expired. Please request a new OTP.' });
      }

      // Valid OTP. Delete it so it cannot be reused.
      await otpsCollection.deleteOne({ _id: validOtp._id });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const newUser = {
      ID: Date.now().toString(),
      CreatedAt: new Date().toISOString(),
      Name: name,
      Email: email || '',
      Phone: phone || '',
      PasswordHash: passwordHash,
      Address: '',
      Measurements: '',
      isVerified: email ? true : false // Email signups are auto-verified, Phone signups require WhatsApp approval
    };

    await collection.insertOne(newUser);

    // Automatically log the user in
    const token = jwt.sign(
      { id: newUser.ID, name: newUser.Name, email: newUser.Email, phone: newUser.Phone },
      process.env.JWT_SECRET || 'dev-secret-key-do-not-use-in-prod',
      { expiresIn: '7d' }
    );

    res.setHeader('Set-Cookie', serialize('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7, // 7 days
      path: '/'
    }));

    res.status(201).json({ 
      success: true, 
      message: 'Registration successful',
      user: { name: newUser.Name, email: newUser.Email, phone: newUser.Phone, isVerified: newUser.isVerified }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database Error: ' + err.message });
  }
};
