<?php
$file = __DIR__.'/system_stats_cache.json';
header('Content-Type: application/json');
echo file_exists($file) ? file_get_contents($file) : json_encode(['ok'=>false]);
