
const { param, body, validationResult } = require("express-validator");

// Validate :ip route param
const validateIPParam = [
  param("ip")
    .trim()
    .notEmpty().withMessage("IP address is required")
    .isLength({ max: 45 }).withMessage("IP address too long")
    .custom(ip => {
      const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6 = /^[0-9a-fA-F:]{2,45}$/;
      if (!ipv4.test(ip) && !ipv6.test(ip)) throw new Error("Invalid IP address format");
      if (ipv4.test(ip)) {
        const parts = ip.split(".");
        if (parts.some(p => parseInt(p) > 255)) throw new Error("Invalid IPv4 address");
      }
      return true;
    }),
  handleValidation
];

// Validate batch body
const validateBatchBody = [
  body("ips")
    .isArray({ min: 1, max: 50 }).withMessage("ips must be an array of 1–50 addresses"),
  body("ips.*")
    .trim()
    .isLength({ max: 45 })
    .custom(ip => {
      const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6 = /^[0-9a-fA-F:]{2,45}$/;
      if (!ipv4.test(ip) && !ipv6.test(ip)) throw new Error(`Invalid IP: ${ip}`);
      return true;
    }),
  handleValidation
];

function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error:  "Validation failed",
      errors: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
}

module.exports = { validateIPParam, validateBatchBody };