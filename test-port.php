<?php
// plugins/check_port/test.php

$result_message = null;
$debug_info = ""; // Initialize as empty string to append

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Ensure FileUtil class is available for getPluginConf
    require_once( dirname(__FILE__)."/../../php/utility/fileutil.php" );
    // Snoopy for making HTTP requests
    require_once( dirname(__FILE__)."/../../php/Snoopy.class.inc" );

    // Load $useIpv4 from the plugin's configuration file (conf.php)
    $useIpv4 = true; // Default value
    @eval( FileUtil::getPluginConf( 'check_port' ) );

    $selected_provider = $_POST['provider'] ?? '';
    $test_ip = trim($_POST['ip'] ?? '');
    $test_port = intval($_POST['port'] ?? 0);

    if (empty($selected_provider) || empty($test_ip) || $test_port <= 0 || $test_port > 65535) {
        $result_message = "Error: Provider, a valid IP address, and a port number (1-65535) are required.";
    } else {
        $checker_url = '';
        $post_data = '';
        // These will be defined specifically for each provider
        $open_indicator_text = null;
        $closed_indicator_text = null;
        $open_indicator_regex = null;
        $closed_indicator_regex = null;

        $provider_specific_setup_done = false;

        $client = new Snoopy();
        $client->useIpv4 = isset($useIpv4) ? $useIpv4 : true;
        // $client->read_timeout = 20; // Optional

        if ($selected_provider == "yougetsignal") {
            $client->agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0";
            $checker_url = "https://ports.yougetsignal.com/check-port.php";
            $open_indicator_text = "is open";
            $closed_indicator_text = "is closed";
            $post_data = "remoteAddress=" . urlencode($test_ip) . "&portNumber=" . urlencode($test_port);
            $provider_specific_setup_done = true;
        } elseif ($selected_provider == "portchecker") {
            $client->agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0";
            $initial_url = "https://portchecker.co/";
            $checker_url = "https://portchecker.co/check-v0";

            // Define indicators based on the observed successful responses from F12
            // For open: Port XX is <span class="green">open</span>.
            // For closed: Port XX is <span class="red">closed</span>.
            $open_indicator_text = 'Port ' . $test_port . ' is <span class="green">open</span>.';
            $closed_indicator_text = 'Port ' . $test_port . ' is <span class="red">closed</span>.';
            
            // Regex versions could also be used for more robustness if needed, e.g.:
            // $open_indicator_regex = '/Port\s+' . $test_port . '\s+is\s+<span class="green">open<\/span>\./is';
            // $closed_indicator_regex = '/Port\s+' . $test_port . '\s+is\s+<span class="red">closed<\/span>\./is';


            $debug_info .= "--- Debug Info for PortChecker.co ---\n";
            $debug_info .= "User-Agent for initial fetch: " . htmlspecialchars($client->agent) . "\n";
            $debug_info .= "Attempting to fetch initial page: " . htmlspecialchars($initial_url) . "\n";

            @$client->fetch($initial_url);
            if ($client->status == 200) {
                $debug_info .= "Successfully fetched " . htmlspecialchars($initial_url) . " (HTTP Status: " . $client->status . ")\n";
                $client->setcookies();

                $debug_info .= "Cookies captured by Snoopy after fetching " . htmlspecialchars($initial_url) . ":\n";
                if (is_array($client->cookies) && !empty($client->cookies)) {
                    foreach ($client->cookies as $cookie_name => $cookie_value) {
                        $debug_info .= "  " . htmlspecialchars($cookie_name) . ": [value hidden for brevity]\n";
                    }
                } else {
                    $debug_info .= "  No cookies captured or cookies array is empty.\n";
                }
                $debug_info .= "\nHeaders from " . htmlspecialchars($initial_url) . " response (Set-Cookie lines are important):\n";
                if (is_array($client->headers) && !empty($client->headers)) {
                    $found_set_cookie = false;
                    foreach ($client->headers as $header_line) {
                        if (stripos($header_line, "Set-Cookie:") === 0) {
                             $debug_info .= "  " . htmlspecialchars(trim($header_line)) . "\n";
                             $found_set_cookie = true;
                        }
                    }
                    if (!$found_set_cookie) {
                        $debug_info .= "  No Set-Cookie headers found in response from " . htmlspecialchars($initial_url) . ".\n";
                    }
                } else {
                     $debug_info .= "  No headers captured or headers array is empty.\n";
                }
                $debug_info .= "\n";

                $csrf_token = '';
                if (preg_match('/name="_csrf" value="(?P<csrf>[^"]+)"/', $client->results, $match_csrf)) {
                    $csrf_token = $match_csrf["csrf"];
                    $debug_info .= "CSRF token extracted from form: " . htmlspecialchars($csrf_token) . "\n";
                } else {
                    $debug_info .= "CSRF token NOT FOUND in form using regex: /name=\"_csrf\" value=\"(?P<csrf>[^\"]+)\"/\n";
                    if (preg_match('/<meta\s+name="csrf-token"\s+content="(?P<csrf_meta>[^"]+)"/i', $client->results, $match_meta_csrf)) {
                        $csrf_token = $match_meta_csrf['csrf_meta'];
                        $debug_info .= "CSRF token found in META TAG: " . htmlspecialchars($csrf_token) . "\n";
                    } else {
                         $debug_info .= "CSRF token also NOT FOUND in meta tag.\n";
                    }
                }

                if (!empty($csrf_token)) {
                    $post_data = "target_ip=" . urlencode($test_ip) . "&port=" . urlencode($test_port) . "&selectPort=" . urlencode($test_port) . "&_csrf=" . urlencode($csrf_token);
                    $provider_specific_setup_done = true;
                    $client->referer = $initial_url; 
                } else {
                    $result_message = "Error: Could not retrieve CSRF token from " . htmlspecialchars($initial_url) . ".";
                    $debug_info .= "Status of fetching " . htmlspecialchars($initial_url) . ": " . $client->status . "\nResponse snippet from " . htmlspecialchars($initial_url) . " (first 3000 chars for CSRF search):\n" . htmlspecialchars(substr($client->results, 0, 3000));
                }
            } else {
                 $result_message = "Error: Could not connect to " . htmlspecialchars($initial_url) . " to get CSRF token. HTTP Status: " . $client->status;
                 $debug_info .= "Snoopy error when fetching " . htmlspecialchars($initial_url) . ": " . htmlspecialchars($client->error) . "\n";
            }
        } else {
            $result_message = "Error: Invalid provider selected.";
        }

        if (empty($result_message) && $provider_specific_setup_done) {
            if ($selected_provider == "portchecker") {
                $client->rawheaders = []; 
                $client->rawheaders["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
                $client->rawheaders["Accept-Language"] = "en-US,en;q=0.5";
                $url_parts_pc = parse_url($initial_url); 
                $client->rawheaders["Origin"] = $url_parts_pc['scheme'] . '://' . $url_parts_pc['host'];
                $client->rawheaders["Connection"] = "keep-alive";
                $client->rawheaders["Upgrade-Insecure-Requests"] = "1";
                $client->rawheaders["Sec-Fetch-Dest"] = "document";
                $client->rawheaders["Sec-Fetch-Mode"] = "navigate";
                $client->rawheaders["Sec-Fetch-Site"] = "same-origin";
                $client->rawheaders["Sec-Fetch-User"] = "?1";

                $debug_info .= "\n--- Headers for POST request to PortChecker.co ---\n";
                $debug_info .= "User-Agent: " . htmlspecialchars($client->agent) . "\n"; 
                $debug_info .= "Referer: " . htmlspecialchars($client->referer) . "\n"; 
                foreach($client->rawheaders as $header_name => $header_value){
                    $debug_info .= htmlspecialchars($header_name) . ": " . htmlspecialchars($header_value) . "\n";
                }

                $debug_info .= "\n--- Cookies Snoopy intends to send with POST (from internal storage) ---\n";
                if (is_array($client->cookies) && !empty($client->cookies)) {
                    $found_relevant_cookie = false;
                    foreach ($client->cookies as $cookie_name => $cookie_value) {
                        $debug_info .= "  " . htmlspecialchars($cookie_name) . ": [value hidden for brevity]\n"; 
                        if ($cookie_name === 'rack.session') {
                            $found_relevant_cookie = true;
                        }
                    }
                    if (!$found_relevant_cookie) {
                         $debug_info .= "  WARNING: rack.session cookie not found in Snoopy's stored cookies before POST.\n";
                    }
                } else {
                    $debug_info .= "  No cookies stored in Snoopy to send with POST.\n";
                }
            }
            
            $debug_info .= "\nPOST data for " . htmlspecialchars($checker_url) . ": " . htmlspecialchars($post_data) . "\n";
            $debug_info .= "\nAttempting to POST to checker URL: " . htmlspecialchars($checker_url) . "\n";
            @$client->fetch($checker_url, "POST", "application/x-www-form-urlencoded", $post_data);

            $status_text_map = ["Unknown", "Closed", "Open"];
            $current_status_val = 0;

            if ($client->status == 200) {
                $debug_info .= "Successfully POSTed to " . htmlspecialchars($checker_url) . " (HTTP Status: " . $client->status . ")\n";
                
                $determined_by_regex = false;
                if (!empty($open_indicator_regex) && preg_match($open_indicator_regex, $client->results)) {
                    $current_status_val = 2; // Open
                    $determined_by_regex = true;
                    $debug_info .= "Status determined as OPEN by regex.\n";
                } elseif (!empty($closed_indicator_regex) && preg_match($closed_indicator_regex, $client->results)) {
                    $current_status_val = 1; // Closed
                    $determined_by_regex = true;
                    $debug_info .= "Status determined as CLOSED by regex.\n";
                }

                if (!$determined_by_regex) {
                    $debug_info .= "Attempting to determine status by text indicators...\n";
                    $debug_info .= "Open indicator text: '" . htmlspecialchars($open_indicator_text ?? 'null') . "'\n";
                    $debug_info .= "Closed indicator text: '" . htmlspecialchars($closed_indicator_text ?? 'null') . "'\n";
                    if (!empty($open_indicator_text) && stripos($client->results, $open_indicator_text) !== false) {
                        $current_status_val = 2; // Open
                        $debug_info .= "Status determined as OPEN by text indicator.\n";
                    } elseif (!empty($closed_indicator_text) && stripos($client->results, $closed_indicator_text) !== false) {
                        $current_status_val = 1; // Closed
                        $debug_info .= "Status determined as CLOSED by text indicator.\n";
                    } else {
                        $debug_info .= "Could not match any text indicators.\n";
                    }
                }
                
                if ($current_status_val == 0) { // If still unknown
                    $result_message = "Could not determine port status from the provider's response. The response format might have changed or the indicators are incorrect. Please check the raw response below.";
                    $debug_info .= "Raw response from " . htmlspecialchars($checker_url) . " (HTTP status " . $client->status . "):\n" . htmlspecialchars(substr($client->results, 0, 4000)); 
                } elseif (empty($result_message)) { 
                    $result_message = "Port <strong>" . htmlspecialchars($test_port) . "</strong> on IP <strong>" . htmlspecialchars($test_ip) . "</strong> (Provider: " . htmlspecialchars($selected_provider) . ") is: <strong>" . $status_text_map[$current_status_val] . "</strong>";
                }

            } else { 
                $current_status_val = 0;
                $result_message = "Error connecting to the checker service (" . htmlspecialchars($checker_url) . "). HTTP Status: " . $client->status . ".";
                $debug_info .= "Snoopy error when POSTing to " . htmlspecialchars($checker_url) . ": " . htmlspecialchars($client->error) . "\nSnoopy results (if any): " . htmlspecialchars(substr($client->results,0,1500)); 
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Port Test Utility</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa; color: #212529; line-height: 1.5; }
        .container { max-width: 700px; margin: 30px auto; padding: 25px; background-color: #ffffff; border: 1px solid #dee2e6; border-radius: 0.3rem; box-shadow: 0 0.5rem 1rem rgba(0,0,0,0.1); }
        h1 { color: #007bff; text-align: center; margin-bottom: 25px; font-weight: 500; }
        label { display: block; margin-top: 1rem; margin-bottom: 0.5rem; font-weight: bold; }
        input[type="text"], input[type="number"], select { width: 100%; padding: 0.75rem; font-size: 1rem; border: 1px solid #ced4da; border-radius: 0.25rem; box-sizing: border-box; transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out; }
        input[type="text"]:focus, input[type="number"]:focus, select:focus { border-color: #80bdff; outline: 0; box-shadow: 0 0 0 0.2rem rgba(0,123,255,0.25); }
        input[type="submit"] { display: block; width: 100%; margin-top: 2rem; padding: 0.75rem 1rem; background-color: #007bff; color: white; border: none; border-radius: 0.25rem; cursor: pointer; font-size: 1.1rem; transition: background-color 0.15s ease-in-out; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .result { margin-top: 2rem; padding: 1.25rem; border: 1px solid #e9ecef; background-color: #f8f9fa; border-radius: 0.25rem; }
        .result h3 { margin-top: 0; color: #007bff; font-weight: 500; }
        .result p { font-size: 1.1em; margin-bottom: 0.5rem; }
        .result strong.status-open { color: #28a745; }
        .result strong.status-closed { color: #dc3545; }
        .result strong.status-unknown { color: #ffc107; }
        .result pre { background-color: #e9ecef; padding: 1rem; border-radius: 0.25rem; white-space: pre-wrap; word-wrap: break-word; max-height: 400px; overflow-y: auto; font-size: 0.9em; color: #495057; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Check Port Test Utility</h1>
        <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
            <div>
                <label for="provider">Provider:</label>
                <select id="provider" name="provider">
                    <option value="yougetsignal" <?php echo (isset($_POST['provider']) && $_POST['provider'] == 'yougetsignal') ? 'selected' : ''; ?>>yougetsignal.com</option>
                    <option value="portchecker" <?php echo (isset($_POST['provider']) && $_POST['provider'] == 'portchecker') ? 'selected' : ''; ?>>portchecker.co</option>
                </select>
            </div>

            <div>
                <label for="ip">IP Address:</label>
                <input type="text" id="ip" name="ip" value="<?php echo htmlspecialchars($_POST['ip'] ?? ''); ?>" required>
            </div>

            <div>
                <label for="port">Port:</label>
                <input type="number" id="port" name="port" value="<?php echo htmlspecialchars($_POST['port'] ?? ''); ?>" required min="1" max="65535">
            </div>

            <input type="submit" value="Test Port">
        </form>

        <?php if ($result_message !== null || !empty($debug_info)): ?>
            <div class="result">
                <?php if ($result_message !== null): ?>
                    <h3>Test Result:</h3>
                    <p>
                        <?php
                        if (strpos($result_message, "Open") !== false) {
                            echo str_replace("<strong>Open</strong>", "<strong class=\"status-open\">Open</strong>", $result_message);
                        } elseif (strpos($result_message, "Closed") !== false) {
                            echo str_replace("<strong>Closed</strong>", "<strong class=\"status-closed\">Closed</strong>", $result_message);
                        } elseif (strpos($result_message, "Unknown") !== false) {
                             echo str_replace("<strong>Unknown</strong>", "<strong class=\"status-unknown\">Unknown</strong>", $result_message);
                        } else {
                            echo $result_message;
                        }
                        ?>
                    </p>
                <?php endif; ?>
                <?php if (!empty($debug_info)): ?>
                    <h4>Debug Information:</h4>
                    <pre><?php echo $debug_info; ?></pre>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
