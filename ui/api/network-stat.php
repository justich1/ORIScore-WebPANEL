<?php
$file = __DIR__.'/system_stats_cache.json';
header('Content-Type: application/json');
if(!file_exists($file)){ echo '{}'; exit; }
$data=json_decode(file_get_contents($file),true);
echo json_encode($data['net']??[]);
