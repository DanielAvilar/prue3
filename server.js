require('dotenv').config();
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const cors = require('cors'); // Importa CORS
const rutas = require('./routes/routes');
const { Options, IntegrationApiKeys, IntegrationCommerceCodes } = require("transbank-sdk");
const { WebpayPlus } = require("transbank-sdk");
const app = express();
const axios = require('axios');
const port = 3000;
const controller = require("./controllers/webpay_plus");
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const vendedorRoutes = require('./routes/vendedor');
const bodegueroRoutes = require('./routes/bodeguero');
const contadorRoutes = require('./routes/contador');
app.use('/vendedor', vendedorRoutes);
app.use('/bodeguero', bodegueroRoutes);
app.use('/contador', contadorRoutes);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

 // Inicializa WebpayPlus con las credenciales

// Configuración de CORS (permitir peticiones desde el frontend)
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true // Permitir el uso de cookies
}));

app.use(session({
  secret: 'ferremas_secreto_seguro',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 60 * 60 * 1000, // 1 hora de duración
    sameSite: 'lax',
    secure: false // Cambiar a true si estás en un entorno HTTPS
  }
}));

// Configuración Webpay (modo sandbox)
const webpay = new WebpayPlus.Transaction(
  new Options(
    IntegrationCommerceCodes.WEBPAY_PLUS,
    IntegrationApiKeys.WEBPAY,
    'https://webpay3gint.transbank.cl' // URL integración (modo sandbox)
  )
);

// Base de datos
const db = new sqlite3.Database('./productos.db', (err) => {
  if (err) return console.error('❌ SQLite error:', err.message);
  console.log('✅ Conectado a SQLite');
});

// ===================== RUTAS =====================

// Productos
// Verificación de sesión para las rutas de productos y carrito
app.get('/productos', (req, res) => {
  if (!req.session.usuario) {
    return res.status(401).json({ error: 'No autenticado, por favor inicie sesión.' });
  }

  db.all("SELECT * FROM productos", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ productos: rows });
  });
});

// Otras rutas de productos y carrito también deben verificar la sesión
app.get('/carrito', (req, res) => {
  const usuario = req.session.usuario;
  if (!usuario) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const query = `
    SELECT p.nombre, p.precio, c.cantidad, p.id as producto_id
    FROM carrito c
    JOIN productos p ON p.id = c.producto_id
    WHERE c.usuario_id = ?
  `;

  db.all(query, [usuario.usuario_id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al obtener carrito' });
    res.json({ carrito: rows });
  });
});

// Registro
app.post('/register', async (req, res) => {
  const { username, email, password, confirmPassword, captcha } = req.body;

  // Validaciones básicas
  if (!username || !email || !password || !confirmPassword || !captcha) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios, incluyendo el captcha' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Las contraseñas no coinciden' });
  }

  // Verificar reCAPTCHA con Google
  const secretKey = process.env.RECAPTCHA_SECRET_KEY;
  const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${captcha}`;

  try {
    // Realizar la solicitud POST a Google para verificar el reCAPTCHA
    const { data } = await axios.post(verifyUrl);

    // Si la verificación de reCAPTCHA falla
    if (!data.success) {
      return res.status(400).json({ error: 'Falló la verificación reCAPTCHA. Inténtalo de nuevo.' });
    }

    // Verificar si el nombre de usuario o el correo ya están en uso
    db.get('SELECT * FROM usuarios WHERE username = ? OR email = ?', [username, email], (err, existingUser) => {
      if (err) {
        console.error('❌ Error en la consulta de usuario:', err);
        return res.status(500).json({ error: 'Error al verificar si el usuario ya existe.' });
      }
      
      if (existingUser) {
        return res.status(400).json({ error: 'El nombre de usuario o correo ya están en uso.' });
      }

      // Encriptar la contraseña
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.error('❌ Error al encriptar la contraseña:', err);
          return res.status(500).json({ error: 'Error al encriptar la contraseña' });
        }

        // Insertar el nuevo usuario en la base de datos
        db.run(`INSERT INTO usuarios (username, email, password) VALUES (?, ?, ?)`, [username, email, hashedPassword], function (err) {
          if (err) {
            console.error('❌ Error al registrar el usuario:', err);
            return res.status(500).json({ error: 'Error al registrar el usuario' });
          }

          // Responder con un mensaje de éxito
          console.log(`✅ Usuario registrado con éxito: ${username}`);
          res.status(201).json({ message: 'Usuario registrado correctamente' });
        });
      });
    });

  } catch (error) {
    console.error('❌ Error al verificar reCAPTCHA:', error.message);
    return res.status(500).json({ error: 'Error al verificar el captcha. Inténtalo más tarde.' });
  }
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM usuarios WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Usuario o contraseña inválidos' });

    bcrypt.compare(password, user.password, (err, match) => {
      if (!match) return res.status(400).json({ error: 'Contraseña incorrecta' });

      // CORREGIDO: usar usuario_id en lugar de id
      req.session.usuario = { username: user.username, usuario_id: user.usuario_id };
      res.json({ message: 'Login exitoso', username: user.username, usuario_id: user.usuario_id });
    });
  });
});


app.post('/carrito/agregar', (req, res) => {
  const { producto_id, cantidad = 1 } = req.body;  // Aseguramos que cantidad siempre tenga un valor
  const usuario = req.session.usuario;  // Obtenemos el usuario de la sesión

  // Validación de usuario
  if (!usuario || !usuario.usuario_id) {
    console.error('⛔ Sesión inválida o falta usuario_id:', req.session.usuario);
    return res.status(401).json({ error: 'Debes iniciar sesión' });
  }

  // Validación de producto
  if (!producto_id) {
    console.error('⛔ Producto no proporcionado:', req.body);
    return res.status(400).json({ error: 'Falta producto_id' });
  }

  // Consulta SQL para agregar al carrito (o actualizar si ya existe)
  const query = `
    INSERT INTO carrito (usuario_id, producto_id, cantidad)
    VALUES (?, ?, ?)
    ON CONFLICT(usuario_id, producto_id) 
    DO UPDATE SET cantidad = cantidad + excluded.cantidad
  `;

  // Ejecución de la consulta
  db.run(query, [usuario.usuario_id, producto_id, cantidad], function(err) {
    if (err) {
      console.error('❌ Error SQL al agregar al carrito:', err.message);
      return res.status(500).json({ error: 'Error del servidor al agregar al carrito' });
    }

    console.log(`✅ Producto agregado al carrito con ID: ${this.lastID}`);
    res.json({ message: 'Producto agregado al carrito', id: this.lastID });
  });
});


app.get('/carrito', (req, res) => {
  const usuario = req.session.usuario;
  if (!usuario) return res.status(401).json({ error: 'No autenticado' });

  const query = `
    SELECT p.id as producto_id, p.nombre, p.precio, c.cantidad
    FROM carrito c
    JOIN productos p ON p.id = c.producto_id
    WHERE c.usuario_id = ?`;

  db.all(query, [usuario.usuario_id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al obtener carrito' });
    res.json({ carrito: rows });
  });
});

//Esto elimina mediante ID loa productos del carrito
app.delete('/carrito/:productoId', (req, res) => {
  const usuario = req.session.usuario;
  const productoId = req.params.productoId;

  if (!usuario) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const query = `DELETE FROM carrito WHERE usuario_id = ? AND producto_id = ?`;

  db.run(query, [usuario.usuario_id, productoId], function(err) {
    if (err) {
      console.error('❌ Error al eliminar producto del carrito:', err.message);
      return res.status(500).json({ error: 'Error al eliminar producto del carrito' });
    }

    res.json({ message: 'Producto eliminado del carrito' });
  });
});

// Actualizar cantidad en el carrito
app.put('/carrito/actualizar', (req, res) => {
  const usuario = req.session.usuario;
  if (!usuario) return res.status(401).json({ error: 'No autenticado' });

  const { producto_id, cantidad } = req.body;
  if (!producto_id || cantidad < 1) return res.status(400).json({ error: 'Datos inválidos' });

  const query = `UPDATE carrito SET cantidad = ? WHERE usuario_id = ? AND producto_id = ?`;

  db.run(query, [cantidad, usuario.usuario_id, producto_id], function (err) {
    if (err) {
      console.error('Error al actualizar la cantidad:', err.message);
      return res.status(500).json({ error: 'Error al actualizar la cantidad' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Producto no encontrado en el carrito' });
    }

    res.json({ message: 'Cantidad actualizada correctamente' });
  });
});

// Función de pago con Webpay Plus
app.post('/pago/webpay', async (req, res) => {
  const usuario = req.session.usuario;
  if (!usuario) return res.status(401).json({ error: 'No autenticado' });

  const query = `
    SELECT p.nombre, p.precio, c.cantidad
    FROM carrito c
    JOIN productos p ON p.id = c.producto_id
    WHERE c.usuario_id = ?
  `;

  db.all(query, [usuario.usuario_id], async (err, productos) => {
    if (err) return res.status(500).json({ error: 'Error al obtener carrito' });
    if (!productos.length) return res.status(400).json({ error: 'Carrito vacío' });

    const total = Math.round(productos.reduce((sum, p) => sum + parseFloat(p.precio) * parseInt(p.cantidad), 0));


    const buyOrder = `ORD-${Date.now()}`;
    const sessionId = `SES-${usuario.usuario_id}-${Date.now()}`;
    const returnUrl = `${req.protocol}://${req.get("host")}/commit`;

    try {
      const response = await webpay.create(buyOrder, sessionId, total, returnUrl);
      res.json({ token: response.token, url: response.url });
    } catch (error) {
      console.error('❌ Error al crear transacción:', error);
      res.status(500).json({ error: 'Error al iniciar transacción con Webpay' });
    }
  });
});


app.post('/commit', async (req, res) => {
  const token = req.body.token_ws || req.query.token_ws;
  if (!token) return res.status(400).send('Token inválido');

  try {
    const response = await new WebpayPlus.Transaction().commit(token);

    console.log('🟢 Transacción exitosa:', response);

    // Guardar la factura
    db.run(
      `INSERT INTO facturas (usuario_id, token, monto, orden, estado, fecha)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [
        req.session.usuario.usuario_id,
        token,
        parseInt(response.amount),
        response.buy_order,
        response.status
      ]
    );

    // Vaciar el carrito
    db.run(`DELETE FROM carrito WHERE usuario_id = ?`, [req.session.usuario.usuario_id]);

    res.redirect('/commit.html');
  } catch (error) {
    console.error('❌ Error al confirmar transacción:', error);
    res.redirect('/commit-error.html');
  }
});

app.get('/commit', async (req, res) => {
  const token = req.query.token_ws;

  if (!token) {
    return res.status(400).send('Token no proporcionado.');
  }

  try {
    const commitResponse = await new WebpayPlus.Transaction().commit(token);

    console.log('🧾 Transacción exitosa:', commitResponse);

    // INSERTAR EN LA TABLA FACTURAS
    await db.run(
      `INSERT INTO facturas (usuario_id, token, monto, orden, estado, fecha)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [
        req.session.usuario.usuario_id,
        token,
        commitResponse.amount,
        commitResponse.buy_order,
        commitResponse.status
      ]
    );

    // VACIAR EL CARRITO DEL USUARIO
    await db.run(
      `DELETE FROM carrito WHERE usuario_id = ?`,
      [req.session.usuario.usuario_id]
    );

    // REDIRIGIR A LA PÁGINA DE ÉXITO
    res.redirect('/commit.html');
  } catch (error) {
    console.error('❌ Error en commit:', error);
    res.redirect('/commit-error.html');
  }
});


app.get('/facturas', (req, res) => {
  const usuarioId = req.session.usuario?.usuario_id;
  if (!usuarioId) return res.status(401).json({ error: 'No autenticado' });

  db.all(
    `SELECT id_transaccion, token, monto, orden, estado, fecha FROM facturas WHERE usuario_id = ? ORDER BY fecha DESC`,
    [usuarioId],
    (err, rows) => {
      if (err) {
        console.error("❌ Error al obtener facturas:", err.message);
        return res.status(500).json({ error: 'Error al obtener facturas' });
      }

      res.json({ facturas: rows });
    }
  );
});

app.get('/session', (req, res) => {
  if (req.session.usuario) {
    res.json({ loggedIn: true, usuario: req.session.usuario });
  } else {
    res.json({ loggedIn: false });
  }
});

// Ruta para cerrar sesión
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Error al cerrar sesión' });
    }
    res.clearCookie('connect.sid'); // Si usas cookies
    res.status(200).json({ message: 'Sesión cerrada exitosamente' });
  });
});

// Inicializar Passport
app.use(passport.initialize());
app.use(passport.session());

// Serializar y deserializar sesión
passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Estrategia de Google
passport.use(new GoogleStrategy({
  clientID: null,
  clientSecret: null,
  callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails[0].value;
  const username = profile.displayName;

  // Buscar usuario existente o crearlo
  db.get('SELECT * FROM usuarios WHERE email = ?', [email], (err, user) => {
    if (err) return done(err);

    if (user) {
      // Usuario ya registrado
      return done(null, {
        usuario_id: user.id,
        username: user.username,
        email: user.email
      });
    } else {
      // Insertar nuevo usuario
      db.run('INSERT INTO usuarios (username, email, password, rol) VALUES (?, ?, ?, ?)',
        [username, email, '', 'cliente'],
        function (err) {
          if (err) return done(err);
          return done(null, {
            usuario_id: this.lastID,
            username,
            email
          });
        });
    }
  });
}));

// Ruta de inicio con Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Ruta de retorno (callback)
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login.html' }),
  (req, res) => {
    // Guardar en sesión el usuario completo
    req.session.usuario = {
      usuario_id: req.user.usuario_id,
      username: req.user.username,
      email: req.user.email
    };
    res.redirect('/dashboard.html');
  }
);

// =================== INICIO DEL SERVIDOR ===================
app.listen(port, () => {
  console.log(`🚀 Servidor en http://localhost:${port}`);
});