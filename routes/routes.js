const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const router = express.Router();

// Conectar a la base de datos SQLite
const db = new sqlite3.Database('./productos.db', (err) => {
  if (err) {
    console.error('❌ Error al conectar a la base de datos', err);
  } else {
    console.log('✅ Conectado a la base de datos SQLite');
  }
});

// ===== PRODUCTOS =====
router.get('/', (req, res) => {
  res.json({ message: 'Bienvenido a la API de productos y carrito de compras' });
});

// Obtener todos los productos
router.get('/productos', (req, res) => {
  db.all("SELECT * FROM productos", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ productos: rows });
  });
});

// Obtener un producto específico
router.get('/productos/:id', (req, res) => {
  const { id } = req.params;
  db.get("SELECT * FROM productos WHERE id = ?", [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json({ producto: row });
  });
});

// Agregar un nuevo producto
router.post('/productos', (req, res) => {
  const { nombre, descripcion, precio, cantidad } = req.body;
  const query = "INSERT INTO productos (nombre, descripcion, precio, cantidad) VALUES (?, ?, ?, ?)";
  db.run(query, [nombre, descripcion, precio, cantidad], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: this.lastID, mensaje: 'Producto agregado exitosamente' });
  });
});

// Actualizar un producto
router.put('/productos/:id', (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, precio, cantidad } = req.body;
  const query = "UPDATE productos SET nombre = ?, descripcion = ?, precio = ?, cantidad = ? WHERE id = ?";
  db.run(query, [nombre, descripcion, precio, cantidad, id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json({ mensaje: 'Producto actualizado exitosamente' });
  });
});

// Eliminar un producto
router.delete('/productos/:id', (req, res) => {
  const { id } = req.params;
  db.run("DELETE FROM productos WHERE id = ?", [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json({ mensaje: 'Producto eliminado exitosamente' });
  });
});

// ===== CARRITO =====

// Verificar si el usuario está autenticado
function verificarSesion(req, res, next) {
  if (!req.session.usuario) {
    return res.status(401).json({ error: 'No autenticado' });
  }
  next();
}

// Agregar un producto al carrito
router.post('/carrito/agregar', verificarSesion, (req, res) => {
  const { producto_id, cantidad } = req.body;
  const usuario_id = req.session.usuario.id;

  const query = `
    INSERT INTO carrito (usuario_id, producto_id, cantidad)
    VALUES (?, ?, ?)
    ON CONFLICT(usuario_id, producto_id)
    DO UPDATE SET cantidad = cantidad + excluded.cantidad
  `;

  db.run(query, [usuario_id, producto_id, cantidad || 1], function(err) {
    if (err) {
      console.error("❌ Error al agregar al carrito:", err.message);
      return res.status(500).json({ error: 'Error al agregar al carrito' });
    }
    res.json({ message: 'Producto agregado al carrito' });
  });
});

// Ver el carrito del usuario
router.get('/carrito', verificarSesion, (req, res) => {
  const usuario_id = req.session.usuario.id;

  const query = `
    SELECT p.nombre, p.precio, c.cantidad
    FROM carrito c
    JOIN productos p ON c.producto_id = p.id
    WHERE c.usuario_id = ?
  `;

  db.all(query, [usuario_id], (err, rows) => {
    if (err) {
      console.error("❌ Error al obtener carrito:", err.message);
      return res.status(500).json({ error: 'Error al obtener carrito' });
    }
    res.json({ carrito: rows });
  });
});

// Eliminar un producto del carrito
router.delete('/carrito/:producto_id', verificarSesion, (req, res) => {
  const usuario_id = req.session.usuario.id;
  const producto_id = req.params.producto_id;

  db.run(
    `DELETE FROM carrito WHERE usuario_id = ? AND producto_id = ?`,
    [usuario_id, producto_id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Error al eliminar producto del carrito' });
      res.json({ message: 'Producto eliminado del carrito' });
    }
  );
});

// Redirigir a Webpay para el pago
router.post('/webpay-retorno', (req, res) => {
  const token = req.body.token_ws;

  // Aquí iría la lógica para confirmar el pago en Webpay
  // Si es exitoso, redirige al usuario a la página de éxito
  // Si hay algún error, lo redirige a la página de fracaso
  res.json({ message: 'Transacción procesada' });
});

module.exports = router;
