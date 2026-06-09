<?php
require __DIR__ . '/_boot.php';
require_admin();
header('Content-Type: text/plain; charset=utf-8');

foreach ([
  'enable_post_data_reading',
  'post_max_size',
  'upload_max_filesize',
  'memory_limit',
  'max_execution_time',
  'max_input_time',
] as $k) {
  echo $k . ' = ' . ini_get($k) . PHP_EOL;
}
