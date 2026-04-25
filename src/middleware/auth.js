const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  const token =
    req.cookies.token ||
    (req.headers.authorization || "").replace("Bearer ", "").trim();

  if (!token) {
    return res.status(401).render("message", {
      title: "Unauthorized",
      message: "Missing token. Please login first.",
      backPath: "/login",
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    req.token = token;
    return next();
  } catch (error) {
    return res.status(401).render("message", {
      title: "Unauthorized",
      message: "Invalid or expired token.",
      backPath: "/login",
    });
  }
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).render("message", {
        title: "Forbidden",
        message: "You are not allowed to access this page.",
        backPath: "/dashboard",
      });
    }

    return next();
  };
}

module.exports = {
  requireAuth,
  requireRole,
};
