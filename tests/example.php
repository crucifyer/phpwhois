<?php

chdir(__DIR__);
include_once '../vendor/autoload.php';

$domain = isset($_SERVER['argv'][1]) ? $_SERVER['argv'][1] : 'github.com'; // not support subdomain.

if(!($info = \Xeno\Net\Whois\Whois::query($domain))) echo "$domain no response\n";

echo $info, "\n";

use \Xeno\Net\Whois\Whois;

if(Whois::isRegistered($info)) {
	echo "$domain was registered\n";
	if(false === ($expiry = Whois::getExpiryDate($info))) {
		echo "expiry date not found\n";
	} else {
		echo "expiry date: $expiry\n";
	}
} else {
	echo "$domain not found\n";
}
