<?php

declare(strict_types=1);

if ($argc < 2 || trim((string)$argv[1]) === '') {
    fwrite(STDERR, "Usage: php make-password-hash.php 'YourStrongPassword'\n");
    exit(1);
}

echo password_hash((string)$argv[1], PASSWORD_DEFAULT) . PHP_EOL;
