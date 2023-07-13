<?php

/**
 * @var string Your API request authorization key from the Call Password section.
 */
const API_ACCESS_KEY = '';

/**
 * @var string Your API request signing key from the Call Password section.
 */
const API_SIGNATURE_KEY = '';

/**
 * @var int Timeout value in seconds for call verification.
 * Possible values: min 30, max 120, default 60.
 */
const TIMEOUT = 60;

/**
 * Generate token for authentication New-tel API.
 *
 * @param string $requestMethod Relative path to call the method.
 * @param int $time Current timestamp.
 * @param string $accessKey API_ACCESS_KEY.
 * @param string $params Request body parameters.
 * @param string $signatureKey API_SIGNATURE_KEY.
 * @return string Token.
 */
function getAuthToken(string $requestMethod, int $time, string $accessKey, string $params, string $signatureKey): string
{
    $hash = implode("\n", [$requestMethod, $time, $accessKey, $params, $signatureKey]);
    return $accessKey . $time . hash("sha256", $hash);
}

/**
 * Handle GET request and load HTML.
 */
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    session_start();
    echo file_get_contents('call-verification.htm');
}

/**
 * Handle the POST request and perform actions based on the 'action' parameter.
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($_GET['action']) {
        case 'start':
            // Start the call verification process.
            $requestBody = json_encode([
                'clientNumber' => $_POST['phoneNumber'],
                'callbackLink' => sprintf("https://%s/?action=callback", $_SERVER['HTTP_HOST']),
                'timeout' => TIMEOUT,
            ]);

            $token = getAuthToken('call-verification/start-inbound-call-waiting', time(),
                API_ACCESS_KEY, $requestBody, API_SIGNATURE_KEY);

            $curl = curl_init('https://api.new-tel.net/call-verification/start-inbound-call-waiting');
            curl_setopt_array($curl, [
                CURLOPT_POST => true,
                CURLOPT_HTTPHEADER => [
                    'Authorization: Bearer ' . $token,
                    'Content-Type: application/json',
                ],
                CURLOPT_POSTFIELDS => $requestBody,
                CURLOPT_RETURNTRANSFER => true,
            ]);

            $response = curl_exec($curl);
            $decodedResponse = json_decode($response, true);

            if ($decodedResponse['status'] === 'success') {
                $callId = $decodedResponse['data']['callDetails']['callId'];

                session_id($callId);
                session_start();

                $_SESSION[$callId] = ['timestamp' => time() + TIMEOUT, 'flag' => false];

                echo json_encode($decodedResponse['data']['callDetails']);
            }
            break;

        case 'check':
            // Check the call confirmation status.
            session_id($_POST['callId']);
            session_start();

            $timeout = $_SESSION[$_POST['callId']]['timestamp'] - time();
            $flag = $_SESSION[$_POST['callId']]['flag'];

            echo json_encode(['timeout' => $timeout, 'flag' => $flag]);
            break;

        case 'callback':
            // Process callback from call verification.
            $body = json_decode(file_get_contents('php://input'), true);

            session_id($body['callId']);
            session_start();

            $_SESSION[$body['callId']]['flag'] = true;
            break;
    }
}
