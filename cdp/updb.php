<?php

define('DB_HOST', "ssh.windelborg.info");
define('DB_NAME', "aau");
define('DB_USERNAME', "aau");
define('DB_PASSWORD', "2387AXumK52aeaSA");

try {
    $conn = new PDO('mysql:host='. DB_HOST .';dbname='. DB_NAME .';charset=utf8', DB_USERNAME, DB_PASSWORD);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->exec("SET CHARACTER SET utf8");
} catch(PDOException $e) {
    echo 'ERROR: ' . $e->getMessage();
}

if ($file = fopen("dk-domains", "r")) {
    while(!feof($file)) {
        $line = fgets($file);
        $stmt = $conn->prepare("INSERT INTO Sites (domain) VALUES (:domain)");
        $stmt->bindParam(":domain", $line);
        $stmt->execute();
    }
    fclose($file);
}

