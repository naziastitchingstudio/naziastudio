const { serialize } = require('cookie');

module.exports = (req, res) => {
  res.setHeader('Set-Cookie', serialize('auth_token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'development',
    sameSite: 'strict',
    maxAge: -1, // Expire immediately
    path: '/'
  }));

  res.status(200).json({ success: true, message: 'Logged out successfully' });
};
