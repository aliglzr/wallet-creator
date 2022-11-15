<?php

require_once "vendor/autoload.php";

use Sop\CryptoTypes\Asymmetric\EC\ECPublicKey;
use Sop\CryptoTypes\Asymmetric\EC\ECPrivateKey;
use Sop\CryptoEncoding\PEM;
use kornrunner\Keccak;

$config = [
    "private_key_bits" => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name' => 'secp256k1'
];
$res = openssl_pkey_new($config);

if (!$res) {
    echo 'ERROR: Fail to generate private key. -> ' . openssl_error_string();
    exit;
}

openssl_pkey_export($res, $private_key);

$key_detail = openssl_pkey_get_details($res);
$pub_key = $key_detail["key"];

$private_pem = PEM::fromString($private_key);

$ec_private_key = ECPrivateKey::fromPEM($private_pem);

$ec_private_seq = $ec_private_key->toASN1();

$private_key_hex = bin2hex($ec_private_seq->at(1)->asOctetString()->string());
$private_key_len = strlen($private_key_hex) / 2;
$pub_key_hex = bin2hex($ec_private_seq->at(3)->asTagged()->asExplicit()->asBitString()->string());
$pub_key_len = strlen($pub_key_hex) / 2;

$pub_key_hex_2 = substr($pub_key_hex, 2);
$pub_key_len_2 = strlen($pub_key_hex_2) / 2;

try {
    $hash = Keccak::hash(hex2bin($pub_key_hex_2), 256);
    $wallet_address = '0x' . substr($hash, -40);
    $wallet_private_key = '0x' . $private_key_hex;

    echo "\r\n   SAVE BUT DO NOT SHARE THIS (Private Key): " . $wallet_private_key;
    echo "\r\n   Address: " . $wallet_address ;
} catch (Exception $e) {
    echo "Error!";
}
