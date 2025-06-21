const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db');


// Crear tablas si no existen
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS productos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      cantidad INTEGER NOT NULL,
      precio INTEGER NOT NULL
    )`);
  
    db.run(`CREATE TABLE IF NOT EXISTS ids_disponibles (
      id INTEGER PRIMARY KEY
    )`);
  });






const getAllProductos = (callback) => {
  db.all('SELECT * FROM productos', [], (err, rows) => {
    callback(err, rows);
  });
};




const getProductoById = (id, callback) => {
  db.get('SELECT * FROM productos WHERE id = ?', [id], (err, row) => {
    callback(err, row);
  });
};




// Función para agregar producto con reutilización de ID
const addProducto = (nombre, cantidad, precio, callback) => {
    db.get('SELECT id FROM ids_disponibles ORDER BY id LIMIT 1', [], (err, row) => {
      if (row) {
        const idDisponible = row.id;
        db.run('INSERT INTO productos (id, nombre, cantidad, precio) VALUES (?, ?, ?, ?)', [idDisponible, nombre, cantidad, precio], function(err) {
          if (err) {
            callback(err, null);
          } else {
            db.run('DELETE FROM ids_disponibles WHERE id = ?', [idDisponible], function(err) {
              callback(err, idDisponible);
            });
          }
        });
      } else {
        db.run('INSERT INTO productos (nombre, cantidad, precio) VALUES (?, ?, ?)', [nombre, cantidad, precio], function(err) {
          callback(err, this.lastID);
        });
      }
    });
  };




const updateProducto = (id, nombre, cantidad, precio, callback) => {
  db.run('UPDATE productos SET nombre = ?, cantidad = ?, precio = ? WHERE id = ?', [nombre, cantidad, precio, id], function(err) {
    callback(err, this.changes);
  });
};




// Función para eliminar producto y marcar el ID como disponible
const deleteProducto = (id, callback) => {
    db.run('DELETE FROM productos WHERE id = ?', [id], function(err) {
      if (err) {
        callback(err, null);
      } else {
        db.run('INSERT INTO ids_disponibles (id) VALUES (?)', [id], function(err) {
          callback(err, this.changes);
        });
      }
    });
  };




const enviarProducto = (id, cantidad, callback) => {
  db.get('SELECT cantidad FROM productos WHERE id = ?', [id], (err, row) => {
    if (err) {
      callback(err, null);
    } else if (row && row.cantidad >= cantidad) {
      const nuevaCantidad = row.cantidad - cantidad;
      db.run('UPDATE productos SET cantidad = ? WHERE id = ?', [nuevaCantidad, id], function(err) {
        callback(err, this.changes);
      });
    } else {
      callback(new Error('Cantidad no disponible o producto no encontrado'), null);
    }
  });
};


module.exports = {
  getAllProductos,
  getProductoById,
  addProducto,
  updateProducto,
  deleteProducto,
  enviarProducto
};
