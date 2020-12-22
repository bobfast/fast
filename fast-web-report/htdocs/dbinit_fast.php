<?php
	include("./dbcon_fast.php");
	$sql="CREATE TABLE Attack_index
	(no int not null auto_increment,
	PRIMARY KEY(no),
	pid int not null,
	hashcheck text,
	procname text,
	targetpath text,
	bit text,
	time_stamp timestamp DEFAULT CURRENT_TIMESTAMP not null
	)";
	if(mysqli_query($db,$sql)){
		echo "  <br>success make table <hr>";
	}else{
		echo "failed";
	}
	$sqli="CREATE TABLE Api_status
	(no int not null auto_increment,
	PRIMARY KEY(no),
	idx int ,
	caller_pid int not null,
	address text,
	size int,
	wapi text,
	callstack text,
	caller_path text)";
	if(mysqli_query($db,$sqli))
	{
		echo "success make table2";
	}
	$sqli_2="CREATE TABLE dump_path
	(no int not null auto_increment,
	PRIMARY KEY(no),
	idx int ,
	dump text)";
	if(mysqli_query($db,$sqli_2))
	{
		echo "success make table2";
	}
	mysqli_close($db);
	
	
	
?>