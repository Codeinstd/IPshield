
// module.exports = async function requireInternalApiKey(
//   req,
//   res,
//   next
// ) {
//   const rawKey = req.headers["x-api-key"];

//   if (!rawKey) {
//     return res.status(401).json({
//       error: "Unauthorized",
//       message: "Missing x-api-key header",
//     });
//   }

//   const apiKey = await resolveKey(rawKey);

//   if (!apiKey || apiKey.role !== "admin") {
//     return res.status(403).json({
//       error: "Forbidden",
//     });
//   }

//   req.apiKey = apiKey;
//   next();
// };