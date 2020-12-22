<?php
	include("./dbcon.php");
	$query ="CREATE DATABASE fast";
	$result =mysqli_query($conn,$query) or die(mysqli_error($conn));
	if($result){
		echo "success create database fast";
	}  
	mysqli_close($conn);
?>