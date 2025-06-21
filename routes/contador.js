const express = require('express');
const path = require('path');
const router = express.Router();

function checkRole(req, res, next) {
  if (req.session.user && req.session.user.rol === 'contador') {
    next();
  } else {
    res.status(403).send('Acceso denegado');
  }
}

router.get('/dashboard', checkRole, (req, res) => {
  res.sendFile(path.join(__dirname, '../public/contador/dashboard.html'));
});

module.exports = router;