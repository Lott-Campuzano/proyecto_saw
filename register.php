<?php session_start(); ?>
<form method="post" action="/autenticacion/sign.php">
    Usuario: <input type="text" name="usuario" required><br>
    Contraseña: <input type="password" name="contraseña" required><br>
     <input type="submit" value="Inicio">
    <input type="hidden" name="registrar" value="1">
<!--     <input type='hidden' name='token' value='<?php echo $_SESSION['token']; ?>'> -->

    <form action="login.php">
    <p>Haz clic aqui para iniciar sesion</p>
    <input type="submit" value="Iniciar sesión">
</form>
</form>
