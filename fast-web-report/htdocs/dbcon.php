<?php

    $host = 'localhost';
    $username = 'root';
    $password = 'root'; 
    $dbname = 'mysql'; 

    header("charset=UTF-8");
    $conn=mysqli_connect($host,$username,$password,$dbname);
if($conn){
	echo "DB Connection Ok";
}else{
	echo "Failed";
}
	
?>

