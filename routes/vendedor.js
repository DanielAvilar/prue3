// routes/vendedor.js
const express = require('express');
const path = require('path');
const router = express.Router();

// Middleware de verificación de rol (opcional)
function checkRole(req, res, next) {
  if (req.session.user && req.session.user.rol === 'vendedor') {
    next();
  } else {
    res.status(403).send('Acceso denegado');
  }
}

router.get('/dashboard', checkRole, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/vendedor/dashboard.html'));
});

module.exports = router;