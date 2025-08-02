<?php
$secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
session_set_cookie_params([
  'lifetime' => 0,
  'path' => '/',
  'domain' => '',
  'secure' => $secure,
  'httponly' => true,
  'samesite' => 'Strict'
]);
session_start();
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Content-Security-Policy: default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net;");

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['initiated'])) {
  session_regenerate_id(true);
  $_SESSION['initiated'] = true;
}
include 'db.php';
include 'includes_header.php';

// Server-side validation function
function validate_login($username, $password) {
  $errors = [];
  if (empty($username) || !preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
    $errors[] = "Username must be 3-30 characters and contain only letters, numbers, and underscores.";
  }
  if (empty($password) || strlen($password) < 6) {
    $errors[] = "Password must be at least 6 characters.";
  }
  return $errors;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $username = trim($_POST['username']);
  $password = $_POST['password'];

  // Get and validate role from POST data
  $role = isset($_POST['role']) ? trim($_POST['role']) : '';
  if (empty($role) || !in_array($role, ['admin', 'editor', 'reader'])) {
    echo "<div class='alert alert-danger'>Please select a valid role.</div>";
  }
  $validation_errors = validate_login($username, $password);
  if (!empty($validation_errors)) {
    foreach ($validation_errors as $error) {
      echo "<div class='alert alert-danger'>{$error}</div>";
    }
  } else {
    // Use prepared statements to prevent SQL injection
    $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();

    if ($user && password_verify($password, $user['password'])) {
      $_SESSION['username'] = $user['username'];
      $_SESSION['role'] = $user['role'];
      // Redirect based on role
      if ($user['role'] === 'admin') {
        header("Location: admin_dashboard.php");
      } else {
        header("Location: dashboard.php");
      }
      exit;
    } else {
      echo "<div class='alert alert-danger'>Invalid credentials. Try again.</div>";
    }
    $stmt->close();
  }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>User Login | ApexPlanet Internship</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- Bootstrap CSS CDN -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: #fff;
      padding: 2.5rem 2rem;
      border-radius: 1rem;
      box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.2);
      max-width: 400px;
      width: 100%;
    }
    .login-container h2 {
      font-weight: 700;
      color: #2575fc;
    }
    .form-label {
      font-weight: 500;
    }
    .btn-primary {
      background: #2575fc;
      border: none;
    }
    .btn-primary:hover {
      background: #6a11cb;
    }
    .alert {
      margin-bottom: 1rem;
    }
    .register-link {
      color: #2575fc;
      text-decoration: none;
    }
    .register-link:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="login-container shadow">
    <h2 class="mb-4">User Login</h2>
    <form method="post">
      <div class="mb-3">
        <label class="form-label">Username</label>
        <input type="text" name="username" class="form-control" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Password</label>
        <input type="password" name="password" class="form-control" required>
      </div>
      <div class="mb-3">
        <label class="form-label">Role</label>
        <select name="role" class="form-control" required>
          <option value="">Select Role</option>
          <option value="admin">Admin</option>
          <option value="editor">Editor</option>
          <option value="reader">Reader</option>
        </select>
      </div>
      <button type="submit" class="btn btn-primary">Login</button>
    </form>
    <p class="mt-3">Don't have an account? <a href="register.php">Register here</a>.</p>
    <?php include 'includes_footer.php'; ?>
  </div>
  <script>
  document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('form');
    form.addEventListener('submit', function(e) {
      let valid = true;
      const username = form.username.value.trim();
      const password = form.password.value;
      let errorMsg = '';

      if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
        errorMsg += 'Username must be 3-30 characters and contain only letters, numbers, and underscores.\n';
        valid = false;
      }
      if (password.length < 6) {
        errorMsg += 'Password must be at least 6 characters.\n';
        valid = false;
      }
      if (!valid) {
        alert(errorMsg);
        e.preventDefault();
      }
    });
  });
  </script>
</body>
</html>

