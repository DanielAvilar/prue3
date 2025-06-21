const { WebpayPlus } = require('transbank-sdk');
const asyncHandler = require('../utils/async_handler');
// Define las credenciales


exports.create = asyncHandler(async (req, res) => {
  const buyOrder = `O-${Math.floor(Math.random() * 10000) + 1}`;
  const sessionId = `S-${Math.floor(Math.random() * 10000) + 1}`;
  const amount = req.body.monto;
  const returnUrl = `${req.protocol}://${req.get('host')}/commit`;

  try {
    // Crear una transacción con las credenciales
    const webpay = new WebpayPlus.Transaction(commerceCode, apiKey); // Aquí pasamos las credenciales al crear la transacción
    const response = await webpay.create(buyOrder, sessionId, amount, returnUrl);

    const { token, url } = response;
    res.json({ token, url });
  } catch (error) {
    console.error('❌ Error al crear transacción:', error);
    res.status(500).json({ error: 'Error al crear transacción' });
  }
});

exports.commit = asyncHandler(async (req, res) => {
  const params = req.method === "GET" ? req.query : req.body;
  const { token_ws, TBK_TOKEN, TBK_ORDEN_COMPRA, TBK_ID_SESION } = params;

  if (token_ws && !TBK_TOKEN) {
    const commitResponse = await new WebpayPlus.Transaction().commit(token_ws);
    console.log("✅ Transacción exitosa:", commitResponse);

    // Guarda en la tabla facturas
    db.run(
      `INSERT INTO facturas (usuario_id, token, monto, orden, estado, fecha)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [
        req.session.usuario.usuario_id,
        token_ws,
        commitResponse.amount,
        commitResponse.buy_order,
        commitResponse.status
      ]
    );

    res.redirect('/commit.html');
  } else {
    res.redirect('/commit-error.html');
  }
});

exports.status = asyncHandler(async (req, res) => {
  const token = req.body.token;
  try {
    const webpay = new WebpayPlus.Transaction(commerceCode, apiKey); // Aquí pasamos las credenciales al crear la transacción
    const statusResponse = await webpay.status(token);
    res.json(statusResponse);
  } catch (error) {
    console.error('❌ Error al obtener el estado:', error);
    res.status(500).json({ error: 'Error al obtener el estado de la transacción' });
  }
});

exports.refund = asyncHandler(async (req, res) => {
  const { token, amount } = req.body;
  try {
    const webpay = new WebpayPlus.Transaction(commerceCode, apiKey); // Aquí pasamos las credenciales al crear la transacción
    const refundResponse = await webpay.refund(token, amount);
    res.json(refundResponse);
  } catch (error) {
    console.error('❌ Error al procesar reembolso:', error);
    res.status(500).json({ error: 'Error al procesar el reembolso' });
  }
});
