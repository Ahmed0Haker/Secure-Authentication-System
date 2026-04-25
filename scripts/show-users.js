const db = require("../src/db");

async function showUsers() {
  const users = await db.all(
    "SELECT id, name, email, role, password_hash, twofa_secret FROM users ORDER BY id ASC"
  );

  if (users.length === 0) {
    // eslint-disable-next-line no-console
    console.log("No users found.");
    return;
  }

  // eslint-disable-next-line no-console
  console.log("Users in database:");
  for (const user of users) {
    // eslint-disable-next-line no-console
    console.log("------------------------------------------------");
    // eslint-disable-next-line no-console
    console.log(`id: ${user.id}`);
    // eslint-disable-next-line no-console
    console.log(`name: ${user.name}`);
    // eslint-disable-next-line no-console
    console.log(`email: ${user.email}`);
    // eslint-disable-next-line no-console
    console.log(`role: ${user.role}`);
    // eslint-disable-next-line no-console
    console.log(`password_hash: ${user.password_hash}`);
    // eslint-disable-next-line no-console
    console.log(`twofa_secret: ${user.twofa_secret}`);
  }
}

showUsers()
  .then(() => process.exit(0))
  .catch((error) => {
    // eslint-disable-next-line no-console
    console.error("Failed to read users:", error.message);
    process.exit(1);
  });
