const apiUrl = 'http://localhost:3000';  // La URL de tu API (debe coincidir con el servidor)

// Verificar si hay una sesión activa
// Función para verificar la sesión activa en el backend
async function verificarSesion() {
  const response = await fetch(`${apiUrl}/session`, { credentials: 'include' });

  const data = await response.json();
  if (data.loggedIn) {
    document.getElementById('username-display').textContent = data.usuario.username;
    return data.usuario;
  } else {
    window.location.href = 'login.html'; // Redirigir al login si no hay sesión activa
  }
}

// Verificar la sesión al cargar el dashboard
document.addEventListener("DOMContentLoaded", async () => {
  await verificarSesion();  // Llama a verificarSesion() cuando se carga la página
});

// Obtener productos desde el backend
async function obtenerProductos() {
  const res = await fetch(`${apiUrl}/productos`, { credentials: 'include' });
  const data = await res.json();
  return data.productos || [];
}

// Renderizar productos en el catálogo
async function renderizarProductos() {
  const productos = await obtenerProductos();
  const contenedor = document.getElementById('productos-list');
  contenedor.innerHTML = '';

  if (!productos.length) {
    contenedor.innerHTML = '<p style="text-align:center">No hay productos disponibles.</p>';
    return;
  }

  productos.forEach(p => {
    const div = document.createElement('div');
    div.classList.add('producto');
    div.innerHTML = `
      <img src="https://via.placeholder.com/150" alt="${p.nombre}">
      <h3>${p.nombre}</h3>
      <p>${p.descripcion}</p>
      <p>$${p.precio.toFixed(2)}</p>
      <button onclick="agregarAlCarrito(${p.id})">Agregar al Carrito</button>
    `;
    contenedor.appendChild(div);
  });
}

// Agregar producto al carrito
async function agregarAlCarrito(productoId) {
  const res = await fetch(`${apiUrl}/carrito/agregar`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ producto_id: productoId, cantidad: 1 }),
    credentials: 'include'
  });

  const data = await res.json();
  alert(res.ok ? 'Producto agregado al carrito' : 'Error: ' + data.error);
}

// Renderizar el carrito de compras
// Renderizar carrito
async function renderizarCarrito() {
  const carritoList = document.getElementById('carrito-list');
  const spinner = document.getElementById('spinner');
  spinner.style.display = 'block'; // Mostrar el spinner mientras se cargan los datos

  try {
    const res = await fetch('http://localhost:3000/carrito', { credentials: 'include' });
    
    if (!res.ok) {
      alert('Error al obtener el carrito');
      return;
    }
    
    const data = await res.json();
    const carrito = data.carrito;

    if (carrito.length === 0) {
      carritoList.innerHTML = '<p>Tu carrito está vacío.</p>';
    } else {
      let total = 0;
      let carritoHTML = '<ul>';

      carrito.forEach(item => {
        total += item.precio * item.cantidad;
        carritoHTML += `
          <li>
            <h3>${item.nombre}</h3>
            <p>Precio: $${item.precio}</p>
            <p>Cantidad: ${item.cantidad}</p>
            <p>Subtotal: $${(item.precio * item.cantidad).toFixed(2)}</p>
            <button onclick="eliminarDelCarrito(${item.producto_id})">Eliminar</button>
          </li>
        `;
      });

      carritoHTML += `</ul>`;
      carritoHTML += `<p>Total: $${total.toFixed(2)}</p>`;
      carritoHTML += `<button onclick="realizarPago()">Realizar Pago</button>`;

      carritoList.innerHTML = carritoHTML;
    }
  } catch (error) {
    console.error("❌ Error al renderizar el carrito:", error);
    carritoList.innerHTML = '<p>Error al cargar los productos del carrito.</p>';
  } finally {
    spinner.style.display = 'none'; // Ocultar el spinner
  }
}

// Actualizar cantidad de un producto
async function actualizarCantidad(productoId, nuevaCantidad) {
  const cantidad = parseInt(nuevaCantidad);
  if (isNaN(cantidad) || cantidad < 1) {
    alert("Cantidad inválida");
    return;
  }

  try {
    const res = await fetch(`${apiUrl}/carrito/actualizar`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ producto_id: productoId, cantidad })
    });

    const data = await res.json();
    if (res.ok) {
      await renderizarCarrito();
    } else {
      alert("Error al actualizar cantidad: " + data.error);
    }
  } catch (err) {
    alert("Error inesperado al actualizar la cantidad.");
  }
}

// Eliminar producto del carrito
async function eliminarDelCarrito(productoId) {
  const res = await fetch(`http://localhost:3000/carrito/${productoId}`, {
    method: 'DELETE',
    credentials: 'include'
  });

  if (res.ok) {
    renderizarCarrito(); // Volver a renderizar el carrito después de eliminar
  } else {
    alert('Error al eliminar el producto del carrito');
  }
}

// Función de pago con integración a Webpay Plus
// Función para manejar el pago
async function realizarPago() {
  const confirmar = confirm('¿Deseas proceder con el pago?');
  if (!confirmar) return;

  try {
    const res = await fetch('http://localhost:3000/pago/webpay', {
      method: 'POST',
      credentials: 'include'
    });

    const data = await res.json();

    if (res.ok && data.url && data.token) {
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = data.url;

      const inputToken = document.createElement('input');
      inputToken.type = 'hidden';
      inputToken.name = 'token_ws';
      inputToken.value = data.token;

      form.appendChild(inputToken);
      document.body.appendChild(form);
      form.submit();
    } else {
      alert("❌ Error al generar transacción Webpay");
    }
  } catch (err) {
    console.error("❌ Error Webpay:", err);
    alert("Ocurrió un error al conectar con Webpay");
  }
}

// Login
// Función para verificar la sesión activa en el backend
async function verificarSesion() {
  const response = await fetch(`${apiUrl}/session`, { credentials: 'include' });

  const data = await response.json();
  if (data.loggedIn) {
    document.getElementById('username-display').textContent = data.usuario.username;
    return data.usuario;
  } else {
    window.location.href = 'login.html'; // Redirigir al login si no hay sesión activa
  }
}

// Verificar la sesión al cargar el dashboard
document.addEventListener("DOMContentLoaded", async () => {
  await verificarSesion();  // Llama a verificarSesion() cuando se carga la página
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

// Dashboard
async function cargarDashboard() {
  const sesion = await verificarSesion();
  if (sesion) {
    document.getElementById('username-display').textContent = sesion.username;
  } else {
    window.location.href = 'login.html';
  }
}

// Logout
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
// Logout
document.getElementById('sign-out').addEventListener('click', () => {
  fetch('/logout', { method: 'POST' })
    .then(response => {
      if (response.ok) {
        window.location.href = 'login.html'; // Redirigir al login después de cerrar sesión
      } else {
        alert('Error al cerrar sesión.');
      }
    })
    .catch(err => {
      console.error('Error en el cierre de sesión:', err);
      alert('Ocurrió un error al cerrar sesión.');
    });
});


// Crear sesión al hacer login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM usuarios WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Usuario o contraseña inválidos' });
    bcrypt.compare(password, user.password, (err, match) => {
      if (!match) return res.status(400).json({ error: 'Contraseña incorrecta' });
      req.session.usuario = { username: user.username, usuario_id: user.id };
      res.json({ message: 'Login exitoso', username: user.username, usuario_id: user.id });
    });
  });
});

async function cargarFacturas() {
  const contenedor = document.getElementById('facturas-container');
  try {
    const res = await fetch(`${apiUrl}/facturas`, { credentials: 'include' });
    const data = await res.json();

    if (!res.ok) {
      contenedor.innerHTML = '<p>No se pudieron cargar las facturas</p>';
      return;
    }

    if (data.facturas.length === 0) {
      contenedor.innerHTML = '<p>No tienes facturas aún</p>';
      return;
    }

    contenedor.innerHTML = '<ul>' + data.facturas.map(f => `
      <li>
        <strong>Orden:</strong> ${f.orden} |
        <strong>Monto:</strong> $${f.monto} |
        <strong>Estado:</strong> ${f.estado} |
        <strong>Fecha:</strong> ${f.fecha}
      </li>
    `).join('') + '</ul>';
  } catch (error) {
    contenedor.innerHTML = '<p>Error al obtener facturas</p>';
  }
}

app.get('/facturas', (req, res) => {
  if (!req.session.usuario) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  db.all(
    `SELECT * FROM facturas WHERE usuario_id = ? ORDER BY fecha DESC`,
    [req.session.usuario.usuario_id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Error al obtener facturas' });
      res.json({ facturas: rows });
    }
  );
});

app.get('/session', (req, res) => {
  if (req.session.usuario) {
    return res.json({ loggedIn: true, usuario: req.session.usuario });
  }
  return res.json({ loggedIn: false });
});


// Inicializar según la página
document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('username-display')) cargarDashboard();
  if (document.getElementById('productos-list')) renderizarProductos();
  if (document.getElementById('carrito-list')) renderizarCarrito();
});
