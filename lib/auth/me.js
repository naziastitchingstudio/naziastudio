const jwt = require('jsonwebtoken');
const { parse } = require('cookie');

module.exports = async (req, res) => {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  
  try {
    const cookies = parse(req.headers.cookie || '');
    const token = cookies.auth_token;

    if (!token) return res.status(401).json({ authenticated: false });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret-key-do-not-use-in-prod');
    
    res.status(200).json({ 
      authenticated: true, 
      user: { name: decoded.name, email: decoded.email }
    });
  } catch (err) {
    res.status(401).json({ authenticated: false });
  }
};
