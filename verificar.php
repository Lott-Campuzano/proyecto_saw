<?php
session_start();
if (isset($_SESSION['verificar'])) {
    echo "<p style='color:red;'>" . $_SESSION['verificar'] . "</p>";
    unset($_SESSION['verificar']);
}

if (isset($_SESSION['msg'])) {
    echo "<p style='color:green;'>" . $_SESSION['msg'] . "</p>";
    unset($_SESSION['msg']);
}
?>
<form method="post" action="process.php">
    Usuario: <input type="text" name="usuario" required><br>
    Token: <input type="text" name="token" required><br>

    <input type="submit" value="Verificar token">
    <input type="hidden" name="verificar" value="1">
</form>