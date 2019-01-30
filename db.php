<?php
	define('DB_HOST', getenv('DB_HOST'));
	define('DB_USER', getenv('DB_USER'));
	define('DB_PASSWORD', getenv('DB_PASSWORD'));
	define('DB_NAME', getenv('DB_NAME'));

	$db_conn = mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME) or 
		die('[!]Could not connect to database ' . mysqli_connect_error());
?>
