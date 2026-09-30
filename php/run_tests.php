<?php
require __DIR__ . '/../../../phpunit_shim.php';
require __DIR__ . '/LombokPDFA.php';
require __DIR__ . '/LombokPDFATest.php';

[$passed, $failed, $failures] = run_shim_test_class('LombokPDFATest');

echo "\n---\n";
echo "Passed: $passed, Failed: $failed\n";
if ($failed > 0) {
    exit(1);
}
