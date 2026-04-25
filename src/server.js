require("dotenv").config();

const path = require("path");
const express = require("express");
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const db = require("./db");
const { requireAuth, requireRole } = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "..", "public")));

function renderError(res, error, fallbackMessage) {
  return res.status(500).render("message", {
    title: "Server Error",
    message: `${fallbackMessage}: ${error.message}`,
    backPath: "/",
  });
}

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const allowedRoles = ["Admin", "Manager", "User"];

  if (!name || !email || !password || !role) {
    return res.status(400).render("register", {
      error: "All fields are required.",
    });
  }

  if (!allowedRoles.includes(role)) {
    return res.status(400).render("register", {
      error: "Role must be Admin, Manager, or User.",
    });
  }

  try {
    const existingUser = await db.get("SELECT id FROM users WHERE email = ?", [
      email.trim().toLowerCase(),
    ]);

    if (existingUser) {
      return res.status(400).render("register", {
        error: "Email already registered.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const secret = speakeasy.generateSecret({
      name: `SecureAuthSystem (${email})`,
    });

    const result = await db.run(
      "INSERT INTO users (name, email, password_hash, role, twofa_secret) VALUES (?, ?, ?, ?, ?)",
      [name.trim(), email.trim().toLowerCase(), passwordHash, role, secret.base32]
    );

    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return res.render("register-success", {
      userId: result.lastID,
      name: name.trim(),
      email: email.trim().toLowerCase(),
      role,
      qrCodeDataUrl,
      manualKey: secret.base32,
    });
  } catch (error) {
    return renderError(res, error, "Failed to register user");
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).render("login", {
      error: "Email and password are required.",
    });
  }

  try {
    const user = await db.get("SELECT * FROM users WHERE email = ?", [
      email.trim().toLowerCase(),
    ]);

    if (!user) {
      return res.status(401).render("login", {
        error: "Invalid credentials.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).render("login", {
        error: "Invalid credentials.",
      });
    }

    return res.render("verify-2fa", {
      error: null,
      email: user.email,
    });
  } catch (error) {
    return renderError(res, error, "Failed to login");
  }
});

app.post("/verify-2fa", async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).render("verify-2fa", {
      error: "Email and 2FA code are required.",
      email: email || "",
    });
  }

  try {
    const user = await db.get("SELECT * FROM users WHERE email = ?", [
      email.trim().toLowerCase(),
    ]);

    if (!user) {
      return res.status(401).render("verify-2fa", {
        error: "Invalid user.",
        email,
      });
    }

    const isCodeValid = speakeasy.totp.verify({
      secret: user.twofa_secret,
      encoding: "base32",
      token: String(code).trim(),
      window: 1,
    });

    if (!isCodeValid) {
      return res.status(401).render("verify-2fa", {
        error: "Invalid 2FA code.",
        email: user.email,
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
    });

    return res.render("token", { token });
  } catch (error) {
    return renderError(res, error, "Failed to verify 2FA");
  }
});

app.post("/set-token", (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).render("message", {
      title: "Invalid Token",
      message: "Token is required.",
      backPath: "/login",
    });
  }

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 60 * 60 * 1000,
  });
  return res.redirect("/dashboard");
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const users = await db.all("SELECT id, name, email, role FROM users ORDER BY id ASC");
    return res.render("dashboard", {
      currentUser: req.user,
      token: req.token,
      users,
    });
  } catch (error) {
    return renderError(res, error, "Failed to load dashboard");
  }
});

app.get("/profile", requireAuth, requireRole(["User"]), (req, res) => {
  return res.render("profile", { currentUser: req.user });
});

app.get("/admin", requireAuth, requireRole(["Admin"]), (req, res) => {
  return res.render("admin", { currentUser: req.user });
});

app.get("/manager", requireAuth, requireRole(["Manager"]), (req, res) => {
  return res.render("manager", { currentUser: req.user });
});

app.get("/user", requireAuth, requireRole(["User"]), (req, res) => {
  return res.render("user", { currentUser: req.user });
});

app.get("/api/me", requireAuth, (req, res) => {
  return res.json({ user: req.user });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Server running at http://localhost:${PORT}`);
});
