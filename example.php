<?php
require_once("./XRCSRF.class.php");

use XRCSRF\XRCSRF;

$csrf = new XRCSRF();

if(isset($_POST["send"])) {
    if(isset($_POST["name"])) {
        if(!empty($_POST["name"])) {
            if($csrf->checkCsrf($_POST)) {
                echo "Valid CSRF";
            } else {
                echo "Invalid CSRF";
            }
        } else {
            echo "Name can not be empty";
        }
    } else {
        echo "Please fill all fields";
    }
}
?>

<form action="" method="POST">
    <input type="text" value="name" placeholder="Name" />
    <button type="submit" name="send" value="Send">
</form>