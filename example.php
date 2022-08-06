<?php

include 'vendor/autoload.php';

use SprayingLuck\Authenticator\DefaultAuth;

$issuer = 'SprayingLuck';
$user = 'sprayingluck@gmail.com';

$authenticator = new DefaultAuth($issuer, $user);

if (isset($_GET['secret']) && isset($_GET['code'])) {
    if ($authenticator::authenticate($_GET['secret'], $_GET['code'])) {
        echo '<script>alert("Authenticated!")</script>';
    }
    else {
        echo '<script>alert("Wrong code!")</script>';
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Google Authenticator</title>
    <style>
        body {
            margin: 50px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row">
            <div class="col-md-6 col-md-offset-3">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h1 class="panel-title">Google Authenticator</h1>
                    </div>
                    <div class="panel-body">
                        <p>
                            <strong>Secret Key:</strong> <?php echo $authenticator->getSecret(); ?><br>
                        </p>
                        <p>
                            <strong>QR Code:</strong>
                        </p>
                        <img src="<?php echo $authenticator->generateQRCode(200); ?>" alt="QR Code" class="img-responsive">
                        <p>
                            <strong>Code:</strong> <?php echo $authenticator->calculateCode($authenticator->getSecret()); ?>
                        </p>
                    </div>
                    <div>
                        <form method="get">
                            <input type="hidden" name="secret" value="<?php echo $authenticator->getSecret(); ?>">
                            <input type="text" name="code" placeholder="Enter your code here">
                            <button type="submit" class="btn btn-primary">Submit</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <hr>


</body>