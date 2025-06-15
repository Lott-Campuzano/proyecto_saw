<?php

header('Content-Type: application/json');

$uploadDir = __DIR__ . '/uploads/';
$relativePath = 'uploads/';

if (!file_exists($uploadDir)) {
    mkdir($uploadDir,0777,true);
}

try {
    if (!isset($_FILES['file'])) {
        throw new Exception( 'No se recibió ningún archivo');
    }

    $file = $_FILES['file'];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        throw new Exception('Error al subir el archivo');
    }

    $safeName = preg_replace( '/[^a-zA-Z0-9.\-_]/', '', basename($file['name']));
    $targetPath = $uploadDir . $safeName;

    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        echo json_encode(['success' => true, 'filename' => $safeName, 'path' => $relativePath . $safeName]);
    } else {
        throw new Exception( 'Error al mover el archivo');
    }
} catch (Exception $e) {
    http_response_code( 400);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

?>