const express = require("express");
const router = express.Router();
const controller = require("../controllers/webpay_plus");
const WebpayPlus = require("transbank-sdk").WebpayPlus;

router.use((req, res, next) => {
  if (process.env.WPP_CC && process.env.WPP_KEY) {
    WebpayPlus.configureForTesting(process.env.WPP_CC, process.env.WPP_KEY);
  } else {
    WebpayPlus.configureForTesting(); // Usa la configuración de prueba si no hay credenciales de producción
  }
  next();
});

router.get("/create", controller.create);
router.post("/create", controller.create);
router.get("/commit", controller.commit); // Añade la ruta para GET
router.post("/commit", controller.commit); // Ruta para POST
router.post("/status", controller.status);
router.post("/refund", controller.refund);
module.exports = router;
