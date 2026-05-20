const jwt = require('jsonwebtoken');
const { getCollection } = require('../db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { account, otp } = req.body;
    
    if (!account || !otp) {
      return res.status(400).json({ error: 'Missing account or otp' });
    }

    const otpsCollection = await getCollection('otps');
    if (!otpsCollection) return res.status(500).json({ error: 'Database configuration missing' });

    // Look up the exact OTP for this account
    const record = await otpsCollection.findOne({ account: account, otp: otp });

    if (!record) {
      return res.status(400).json({ error: 'Invalid verification code!' });
    }

    // Check expiration
    if (new Date() > new Date(record.expiresAt)) {
      // OTP expired, clean it up
      await otpsCollection.deleteOne({ _id: record._id });
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }

    // OTP is valid! Delete it so it cannot be reused.
    await otpsCollection.deleteOne({ _id: record._id });
    
    // Generate a temporary reset token valid for 15 minutes
    const token = jwt.sign(
      { account, resetAllowed: true },
      process.env.JWT_SECRET || 'dev-secret-key-do-not-use-in-prod',
      { expiresIn: '15m' }
    );
    
    res.status(200).json({ 
      success: true, 
      token 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server Error: ' + err.message });
  }
};
