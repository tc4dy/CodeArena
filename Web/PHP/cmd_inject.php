<?php
if(isset($_GET['ping'])){
    $ip = $_GET['ping'];
    echo shell_exec("ping -c 1 " . $ip);
}else{
    echo "<form><input name='ping'><input type=submit></form>";
}
?>