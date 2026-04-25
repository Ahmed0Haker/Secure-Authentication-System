require("dotenv").config();
const bcrypt = require("bcryptjs");
const speakeasy = require("speakeasy");
const db = require("../src/db");

const demoUsers = [
  {
    name: "Admin Demo",
    email: "admin@example.com",
    password: "Admin@123",
    role: "Admin",
  },
  {
    name: "Manager Demo",
    email: "manager@example.com",
    password: "Manager@123",
    role: "Manager",
  },
  {
    name: "User Demo",
    email: "user@example.com",
    password: "User@123",
    role: "User",
  },
];

async function seed() {
  for (const user of demoUsers) {
    const existing = await db.get("SELECT id FROM users WHERE email = ?", [user.email]);
    if (existing) {
      // eslint-disable-next-line no-console
      console.log(`Skipping existing user: ${user.email}`);
      continue;
    }

    const hash = await bcrypt.hash(user.password, 12);
    const secret = speakeasy.generateSecret({
      name: `SecureAuthSystem (${user.email})`,
    });

    await db.run(
      "INSERT INTO users (name, email, password_hash, role, twofa_secret) VALUES (?, ?, ?, ?, ?)",
      [user.name, user.email, hash, user.role, secret.base32]
    );

    // eslint-disable-next-line no-console
    console.log(`Created: ${user.email} | role=${user.role} | password=${user.password}`);
  }
}

seed()
  .then(() => {
    // eslint-disable-next-line no-console
    console.log("Seeding completed.");
    process.exit(0);
  })
  .catch((error) => {
    // eslint-disable-next-line no-console
    console.error("Seeding failed:", error.message);
    process.exit(1);
  });
