<?php
declare(strict_types=1);
function render(PDO $pdo, string $title, callable $fn): void {
  ob_start();
  $fn();
  $content = ob_get_clean();
  require __DIR__ . '/_layout.php';
}
