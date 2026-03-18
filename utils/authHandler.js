const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Đọc khóa private và public
const privateKey = fs.readFileSync(path.join(__dirname, '../private.pem'), 'utf8');
const publicKey = fs.readFileSync(path.join(__dirname, '../public.pem'), 'utf8');

module.exports = {
  // Tạo JWT token với RS256
  generateToken: function (payload) {
    try {
      const token = jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        expiresIn: '24h'
      });
      return token;
    } catch (error) {
      throw new Error('Cannot generate token: ' + error.message);
    }
  },

  // Xác minh token
  verifyToken: function (token) {
    try {
      const decoded = jwt.verify(token, publicKey, {
        algorithms: ['RS256']
      });
      return decoded;
    } catch (error) {
      throw new Error('Token is invalid: ' + error.message);
    }
  },

  // Middleware xác thực
  authenticateToken: function (req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        message: 'Access token is required'
      });
    }

    try {
      const decoded = jwt.verify(token, publicKey, {
        algorithms: ['RS256']
      });
      req.userId = decoded.userId;
      req.user = decoded;
      next();
    } catch (error) {
      return res.status(403).json({
        message: 'Invalid or expired token'
      });
    }
  }
};
