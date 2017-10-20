<?php

chdir(__DIR__);
include_once '../vendor/autoload.php';

$domain = '한국인.한국'; // not support subdomain.

$info = \Xeno\Net\Whois\Whois::query($domain);

echo $info, "\n";

use \Xeno\Net\Whois\Whois;

if(Whois::isRegistered($info, $domain)) {
	echo "$domain was registered\n";
	if(false === ($expiry = Whois::getExpiryDate($info))) {
		echo "expiry date not found\n";
	} else {
		echo 'expiry date: ', $expiry, "\n";
	}
} else {
	echo "$domain not found\n";
}
