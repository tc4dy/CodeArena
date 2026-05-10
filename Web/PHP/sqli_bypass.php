<?php
$db=new PDO('sqlite:../data/ctf.db');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$user=$_POST['user']??$_GET['user']??'';
$pass=$_POST['pass']??$_GET['pass']??'';
if(strlen($user)>100||strlen($pass)>100){http_response_code(400);die("too long");}
$stmt=$db->query("SELECT * FROM users WHERE username='$user' AND password='$pass'");
if($row=$stmt->fetch()){
    echo "FLAG{SQLi_Bypass_Success_".md5($row['username'])."}";
}else{
    http_response_code(403);
    echo "INVALID_CREDENTIALS";
}
?>