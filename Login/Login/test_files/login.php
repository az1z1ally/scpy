<?php

$username = $_POST["username"];
$password = $_POST["password"];

$loginok = 0;

if($username == "admin") {
  if($password == "thispasswordwillwork") {
   $loginok = 1; 
  }
}

if($loginok == 1) {
  $content = "<h1>Welcome ".$username."!</h1>";
} else {
  $content = <<<EOT
             <form id='login_form' method='post' action='login.php'>
             <h2> Please enter your username and password </h2>
             Username: <input id='username' name='username' type='text'/></br>
             Password: <input id='password' name='password' type='password'/></br>
             <input type='submit'/>
             </form>
  EOT;
}
echo "
<html>
<title>Login!</title>
<head></head>
<body>$content</body>
</html>
";

?>
