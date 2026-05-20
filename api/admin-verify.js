const { getCollection } = require('../lib/db');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const { phone, secret } = req.body;
    
    // In a real app, use an environment variable for ADMIN_SECRET
    const ADMIN_SECRET = process.env.ADMIN_SECRET || 'naziastudio-admin-key-2026';
    
    if (secret !== ADMIN_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (!phone) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    const collection = await getCollection('users');
    if (!collection) return res.status(500).json({ error: 'Database configuration missing' });

    // Format phone just in case (ensure + sign is there if provided without it)
    let searchPhone = phone;
    if (!searchPhone.startsWith('+')) searchPhone = '+' + searchPhone;

    const result = await collection.updateOne(
      { Phone: searchPhone },
      { $set: { isVerified: true } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'User not found with this phone number' });
    }

    res.status(200).json({ success: true, message: `User ${searchPhone} successfully verified.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database Error: ' + err.message });
  }
};
