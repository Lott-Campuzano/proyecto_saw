<?php
session_start();
$pdo = new PDO('mysql:host=localhost;dbname=mi_base', 'user', 'pass');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
ob_start();

    $user = filter_input(INPUT_POST, 'usuario', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $pass = $_POST['contraseña'];

if (!empty($user) && !empty($pass)) {
    try {
        // Revisamos que el usuario exista antes de registrarlo
        $checkStmt = $pdo->prepare("SELECT COUNT(*) FROM logs WHERE user = :username");
        $checkStmt->bindParam(':username', $user);
        $checkStmt->execute();
        $existe = $checkStmt->fetchColumn();
        echo htmlspecialchars($user);

        if ($existe) {
            echo "Este usuario ya existe.";
        } else {
            $hashedPassword = password_hash($pass, PASSWORD_DEFAULT);

            $stmt = $pdo->prepare("INSERT INTO logs (user, pass) VALUES (:username, :password)");
            $stmt->bindParam(':username', $user);
            $stmt->bindParam(':password', $hashedPassword);
            echo htmlspecialchars($user);

            if ($stmt->execute()) {
                echo "Te has registrado con éxito.";
            } else {
                echo "Error al registrar el usuario.";
            }
        }
    } catch (PDOException $e) {
        echo "Error: " . $e->getMessage();
    }
}
?>
