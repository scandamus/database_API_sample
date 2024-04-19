<?php
$accessToken = $_SERVER['X_AUTH_HEADER'];
$url = 'https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses,photos';
$ch = curl_init($url);
$headers = [
    'Authorization: Bearer ' . $accessToken,
    'Accept: application/json'
];

curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

if (!curl_exec($ch)) {
    die('Error: cURL: ' . curl_error($ch));
}

$response = curl_exec($ch);
$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$username = "Jane done";
$email = "";
$photourl = "";

if ($httpcode == 200) {
    $responseData = json_decode($response, true);
    $username = $responseData['names'][0]['displayName'];
    $email = $responseData['emailAddresses'][0]['value'];
    if (!empty($responseData['photos']) && !empty($responseData['photos'][0]['url'])) {
	    $photoUrl = $responseData['photos'][0]['url'];
    } else {
    echo "Error: API Request status: " . $httpcode . "\n";
    echo "Response: " . $response . "\n";
    }
}
?>
<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>Secret Page</title>
  <link rel="stylesheet" href="./style.css">

</head>
<body>

<div class="container">
  <div class="card">
    <?php if (!empty($photoUrl)): ?>
      <div class="photo">
        <img src="<?php echo htmlspecialchars($photoUrl, ENT_QUOTES, 'UTF-8'); ?>" alt="Profile Photo">
      </div>
    <?php endif; ?>
    <h1 class="name"><?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></h1>
    <div class="info">
      <p><span class="property">Email: </span><?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?></p>
    </div>
  </div>
  <div class="logout">
    <a href="/oauth2/sign_out?rd=/oauth2/sign_in">LOGOUT</a>
  </div>
</div>

</body>
</html>
