<?php
	$email = $password = "";
	$errors = array();
	if($_SERVER['REQUEST_METHOD'] == 'POST'){
		$email = filter_var($_POST['password'], FILTER_SANITIZE_STRING);
		$password = filter_var($_POST['password'], FILTER_SANITIZE_STRING);

		if(empty($email) || filter_var($email, FILTER_VALIDATE_EMAIL)){
			$errors[] = 'please enter your email';
			$errors[] = 'please enter a valid email address';
		}
		else if(empty($password))$errors[] = 'Authentication failed due to empty password';
		else{	
			require('../db.php');
			$query = "SELECT username, password FROM users WHERE email=?";
			$stmt = mysqli_stmt_init($db_conn);

			mysqli_stmt_prepare($stmt, $query);
			mysqli_stmt_bind_param($stmt, "s", $email);
			mysqli_stmt_execute($stmt);
			
			$results = mysqli_stmt_get_result($stmt);
			$row = mysqli_stmt_fetch_row($stmt, MYSQLI_NUM);
			if(mysqli_num_rows($result) == 1){
				if(password_verify($password, $row[1])){
					session_start();
					$_SESSION['username'] = row[0];
					$_SESSION['loggedin'] = true;
					header("Location: account.php");
				}
			}
			else $errors[] = 'Account not found';	
		} 
	}
	if(!empty($errors)){
		$err_msg = "These errors occured while processing your credentials <br />";
		foreach($errors as $error){
			$err_msg .= $error;
		}
		$err_msg .= "<br />Please try again";
	}
	mysqli_stmt_free_result($stmt);
	mysqli_stmt_close($db_conn);
?>
