<?php

header('Content-Type: application/json');

$uploadDir = __DIR__ . '/uploads/';

try {
    $data = json_decode(file_get_contents('php://input'), true);

    if (!isset($data['filename'])) {
        throw new Exception('Nombre de archivo no especificado');
    }

    $safeName = basename($data['filename']);
    $filePath = $uploadDir . $safeName;

    if (!file_exists($filePath)) {
        throw new Exception('El archivo no existe');
    }

    if (unlink($filePath)) {
        echo json_encode(['success' => true, 'message' => 'Archivo eliminado correctamente']);
    } else {
        throw new Exception( 'Error al eliminar el archivo');
    }
} catch (Exception $e) {
    http_response_code( 400);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}

?>