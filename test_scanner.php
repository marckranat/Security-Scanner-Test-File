<?php
/**
 * Security Scanner Test File - PHP Edition
 * This file is designed to test server-side AV scanners
 * It contains NO malicious code, only suspicious patterns
 */

// JavaScript in head? Bad practice. JavaScript in body? Also bad practice.
// Let's do both, plus inline, plus obfuscated!
?>
<!DOCTYPE html>
<html>
<head>
    <title>Security Scanner Test</title>
    <script>
        // Suspicious inline JavaScript in head
        var _0x4f3a=['eval','base64','decode','fromCharCode'];
        function _0x2b1c(_0x1a2d,_0x3e4f){return String.fromCharCode(_0x1a2d^_0x3e4f);}
    </script>
</head>
<body>
    <h1>Scanner Test Page</h1>
    <script>
        // More JavaScript in body - double trouble!
        var encoded='PHNjcmlwdD5hbGVydCgnU2Nhbm5lciBUZXN0Jyk7PC9zY3JpcHQ+';
        var decoded=atob(encoded);
        // Don't actually eval this, but the pattern is suspicious
        // eval(decoded); // Commented out but pattern exists
    </script>
    
    <?php
    // Layer 1: Base64 encoded string
    $layer1 = 'ZXZhbCgnZWNobyAiSGVsbG8gV29ybGQiOycpOw==';
    
    // Layer 2: Hex encoded
    $layer2 = '6576616c286261736536345f6465636f646528272e2e2e2729293b';
    
    // Layer 3: Double base64
    $layer3 = base64_encode(base64_encode('eval("echo \'test\';");'));
    
    // Layer 4: ROT13 + Base64
    $layer4 = base64_encode(str_rot13('riny("rpub \'grfg\';");'));
    
    // Decode and show (but don't execute)
    $decoded1 = base64_decode($layer1);
    $decoded2 = hex2bin($layer2);
    $decoded3 = base64_decode(base64_decode($layer3));
    $decoded4 = str_rot13(base64_decode($layer4));
    
    // Suspicious function calls that scanners look for
    $suspicious_functions = [
        'eval',
        'exec',
        'system',
        'shell_exec',
        'passthru',
        'popen',
        'proc_open',
        'file_get_contents',
        'fopen',
        'curl_exec',
        'base64_decode',
        'gzinflate',
        'str_rot13',
        'hex2bin'
    ];
    
    // Create a string that looks like it might be executed
    $code_string = '$result = ' . implode('(', $suspicious_functions) . ';';
    
    // File operations (read-only, harmless)
    if (file_exists(__FILE__)) {
        $file_content = file_get_contents(__FILE__);
        $file_size = filesize(__FILE__);
    }
    
    // Network-like operations (but not actually connecting)
    $url_parts = parse_url('http://example.com/test');
    $ip_address = gethostbyname('localhost');
    
    // Obfuscated variable names
    ${chr(95).chr(120).chr(53).chr(48)} = 'TEST';
    ${"\x5f\x30\x78\x34\x66\x33\x61"} = 'VALUE';
    
    // Dynamic function calls
    $func_name = 'base' . '64' . '_' . 'decode';
    $test_var = $func_name('SGVsbG8=');
    
    // Nested encoding
    $nested = base64_encode(gzcompress(str_rot13(hex2bin('48656c6c6f'))));
    
    // Suspicious patterns
    $pattern1 = '<?php eval($_POST["cmd"]); ?>'; // String, not executed
    $pattern2 = '<?php system($_GET["x"]); ?>';  // String, not executed
    $pattern3 = '<?php assert($_REQUEST["a"]); ?>'; // String, not executed
    
    // JavaScript injection pattern (as string, not executed)
    $js_inject = '<script>document.cookie</script>';
    $xss_pattern = 'javascript:alert(1)';
    
    // SQL injection pattern (as string, not executed)
    $sql_pattern = "'; DROP TABLE users; --";
    
    // Command injection pattern (as string, not executed)
    $cmd_pattern = '; cat /etc/passwd';
    
    // Display information (harmless)
    echo "<!-- Scanner Test File -->\n";
    echo "<!-- This file tests AV scanner detection capabilities -->\n";
    echo "<!-- All suspicious patterns are stored as strings and never executed -->\n";
    echo "<p>File size: " . htmlspecialchars($file_size) . " bytes</p>\n";
    echo "<p>Test variable: " . htmlspecialchars($test_var) . "</p>\n";
    echo "<p>Scanner test file loaded successfully</p>\n";
    
    // Create a closure that looks suspicious but does nothing
    $closure = function($input) {
        $decoded = base64_decode($input);
        $rotated = str_rot13($decoded);
        $hexed = bin2hex($rotated);
        return $hexed; // Just return, don't execute
    };
    
    // Test the closure with harmless input
    $result = $closure('SGVsbG8=');
    
    // Array of encoded strings
    $encoded_array = [
        base64_encode('eval'),
        base64_encode('exec'),
        base64_encode('system'),
        hex2bin('6576616c'),
        str_rot13('riny'),
        gzcompress('eval')
    ];
    
    // Reflection API usage (can be used for obfuscation)
    $reflection = new ReflectionFunction('base64_decode');
    $reflection_name = $reflection->getName();
    
    // Variable variables
    $var_name = 'test';
    $$var_name = 'value';
    ${'var' . '_' . 'name'} = 'another';
    
    // Callback functions
    $callbacks = [
        'base64_decode',
        'str_rot13',
        'hex2bin',
        'gzuncompress'
    ];
    
    foreach ($callbacks as $cb) {
        if (function_exists($cb)) {
            // Function exists, but we don't call it on user input
        }
    }
    
    // Serialized data (can hide malicious code)
    $serialized = serialize(['func' => 'eval', 'code' => 'echo "test";']);
    $unserialized = unserialize($serialized); // Harmless unserialization
    
    // Regular expressions that might match suspicious patterns
    $regex_patterns = [
        '/eval\s*\(/i',
        '/exec\s*\(/i',
        '/system\s*\(/i',
        '/base64_decode\s*\(/i',
        '/\$_POST/i',
        '/\$_GET/i',
        '/\$_REQUEST/i',
        '/\$_COOKIE/i',
        '/\$_SERVER/i'
    ];
    
    // Check if patterns exist (but don't execute)
    foreach ($regex_patterns as $pattern) {
        if (preg_match($pattern, $code_string)) {
            // Pattern found, but we don't execute
        }
    }
    
    // End of file - all patterns are present but none are executed
    ?>
    
    <script>
        // Final JavaScript in body
        var test_complete = true;
    </script>
</body>
</html>

