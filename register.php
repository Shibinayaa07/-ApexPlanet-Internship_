<?php
// Define allowed roles
$allowed_roles = ['editor', 'reader'];

// Secure session settings
session_set_cookie_params([
  'httponly' => true,
  'secure' => isset($_SERVER['HTTPS']),
  'samesite' => 'Strict'
]);
session_start();

// Redirect logged-in users
if (isset($_SESSION['user_id'])) {
  header('Location: dashboard.php');
  exit();
}

include 'db.php';
include 'includes_header.php';

// Server-side form validation and prepared statements
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Basic server-side validation
  $username = trim($_POST['username'] ?? '');
  $password_raw = $_POST['password'] ?? '';
  $role = in_array($_POST['role'] ?? '', $allowed_roles) ? $_POST['role'] : 'reader';

  if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $username)) {
    // Do not display error
  } elseif (strlen($password_raw) < 6 || strlen($password_raw) > 64) {
    // Do not display error
  } else {
    // Prepared statement to check for existing user
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
      // Do not display error
    } else {
      $password = password_hash($password_raw, PASSWORD_DEFAULT);

      // Prepared statement to insert new user
      $stmt_insert = $conn->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
      $stmt_insert->bind_param("sss", $username, $password, $role);
      if ($stmt_insert->execute()) {
        $message = "<div class='alert alert-success'>Registration successful. <a href='login.php'>Login now</a>.</div>";
      }
      $stmt_insert->close();
    }
    $stmt->close();
  }
}
?>
<script>
// Client-side validation
document.addEventListener('DOMContentLoaded', function() {
  const form = document.querySelector('form');
  form.addEventListener('submit', function(e) {
    const username = form.username.value.trim();
    const password = form.password.value;
    let valid = true;
    let msg = '';

    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      valid = false;
      msg += 'Username must be 3-32 characters and contain only letters, numbers, and underscores.\n';
    }
    if (password.length < 6 || password.length > 64) {
      valid = false;
      msg += 'Password must be between 6 and 64 characters.\n';
    }
    if (!valid) {
      alert(msg);
      e.preventDefault();
    }
  });
});
</script>
<div class="container d-flex justify-content-center align-items-center" style="min-height: 80vh;">
  <div class="card shadow p-4" style="max-width: 400px; width: 100%;">
    <h2 class="mb-4 text-center">Create Account</h2>
    <?php if (!empty($message)) echo $message; ?>
    <form method="post" autocomplete="off">
      <div class="mb-3">
        <label class="form-label">Username</label>
        <input type="text" name="username" class="form-control" required minlength="3" maxlength="32" autofocus>
      </div>
      <div class="mb-3">
        <label class="form-label">Password</label>
        <input type="password" name="password" class="form-control" required minlength="6" maxlength="64">
      </div>
      <button type="submit" class="btn btn-primary w-100">Register</button>
      <div class="mt-3 text-center">
        <small>Already have an account? <a href="login.php">Login</a></small>
      </div>
    </form>
  </div>
</div>
<?php include 'includes_footer.php'; ?>
