<?php session_start(); ?>
<form method="post" action="process.php">
    Usuario: <input type="text" name="usuario" required><br>
    Contraseña: <input type="password" name="contraseña" required><br>
     <input type="submit" value="Inicio">
    <input type="hidden" name="login" value="1">
</form>
<wbr>
<form action="register.php">
    <p>Haz clic aqui para unirte</p>
    <input type="submit" value="Crear cuenta">
     <input type="hidden" name="verificar" value="1">
</form>