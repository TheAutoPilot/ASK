<?php
	session_start();
	if(isset($_SESSION['loggedin']) && isset($_SESSION['username'])){
		if(session_status() == PHP_SESSION_ACTIVE){
			session_destroy();
			header('Location: ../index.php');
		}
	}
	else{
		header('Location: ../index.php');
		exit();
	}
?>
