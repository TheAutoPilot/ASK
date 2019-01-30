<?php

	$name = $username = $email = $password = $confirm_password = $pass_hash = "";
	$errors = array();
	if($_SERVER['REQUEST_METHOD'] == 'POST'){

		$name = filter_var($_POST['name'], FILTER_SANITIZE_STRING);
		$username = filter_var($_POST['username'],FILTER_SANITIZE_STRING);
		$email = filter_var($_POST['email'], FILTER_SANITIZE_STRING);
		$password = filter_var($_POST['password'], FILTER_SANITIZE_STRING);
		$password_confirm = filter_var($_POST['password_confirm'], FILTER_SANITIZE_STRING);
		
		if(empty($name) || !preg_match("/[A-Za-z ]*$/", $name)){
			$erors[] = "Invalid Username";
			$errors[] = "Username is empty";
		}
		else if(empty($username) || !preg_match("/[A-Za-z0-9 ]*$/", $username)){
			$errors[] = 'Username is required and should not be empty';
		}
		else if(empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)){
			$errors[] = 'Invalid Email Format';
			$errors[] = 'Email Empty';
		}
		else{
			require_once('../db.php');
			$query = "SELECT 1 FROM users WHERE username =? OR email =?";
			$stmt = mysqli_stmt_init($db_conn);
			
			mysqli_stmt_prepare($stmt, $query);
			mysqli_stmt_bind_param($stmt, "ss", $username, $email);
			mysqli_stmt_execute($stmt);

			$res = mysqli_stmt_get_result($stmt);
			$rows = mysqli_num_rows($res);
			if($rows > 0){
				$errors[] = 'Username/Email already taken';
			}

			mysqli_stmt_free_result($stmt);
			mysqli_stmt_close($stmt);	
		}
		if(empty($password) || empty($password_confirm)){
			$errors[] = 'Password Fields should not be left empty';
		}
		else{
			$pass_len = strlen($password);
			if($pass_len < 8)$errors[] = 'Password length too short';
			else{
				if(!strcmp($password, $password_confirm)){
					$pass_hash = password_hash($password, PASSWORD_DEFAULT);
				}
				else{
					$errors[] = 'Password and Confirm Password do not match';
				}
			}
		}
	}
	if(empty($errors)){
		require_once('../db.php');
		$query = "INSERT INTO users(_name, username, email, _password) VALUES(?,?,?,?)";
		$stmt = mysqli_stmt_init($db_conn);
		
		mysqli_stmt_prepare($stmt, $query);
		mysqli_stmt_bind_param($stmt, "ssss", $name, $username, $email, $pass_hash);
		mysqli_stmt_execute($stmt);

		if(mysqli_stmt_affected_rows($stmt) > 0){
			session_start();
			$_SESSION['name'] = $name;
			$_SESSION['loggedin'] = true;
			header("Location: account_unconfirmed.php");
		}
	}
	else{
		$error_msg = "";
		foreach($errors as $error){
			$error_msg .= $error;
		}	
		$error_msg .= "<br /> Please try again.";
		echo $error_msg;
	}

?>
