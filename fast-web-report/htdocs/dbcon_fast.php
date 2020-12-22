<?php
	
	$host = 'localhost';
   	$username = 'root'; # MySQL 계정 아이디
  	$password = 'root'; # MySQL 계정 패스워드
  	$dbname = 'fast';  # DATABASE 이름

   	header("charset=UTF-8");
   	$db=mysqli_connect($host,$username,$password,$dbname);
	if($db){
	}else{
		echo "Failed";
	}
?>