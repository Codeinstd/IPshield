function errorHandler(err, req, res, next) {
  console.error("[UNHANDLED ERROR]", err);

  // Default values (safe fallback)
  let statusCode = err.status || 500;
  let message = "Internal Server Error";

  // Handle known / trusted errors
  if (err.name === "ValidationError") {
    statusCode = 400;
    message = err.message;
  }

  if (err.name === "UnauthorizedError") {
    statusCode = 401;
    message = "Unauthorized";
  }

  // PostgreSQL errors (DO NOT leak details)
  if (err.code && err.code.startsWith("23")) {
    // constraint / db-related error
    statusCode = 400;
    message = "Database constraint violation";
  }

  // Optional: custom app errors
  if (err.isOperational) {
    statusCode = err.status || 400;
    message = err.message;
  }

  res.status(statusCode).json({
    error: message,
  });
}

module.exports = { errorHandler };