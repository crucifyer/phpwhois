<?php

include_once '../vendor/autoload.php';

$domain = 'github.com'; // not support subdomain.

$info = \Xeno\Net\Whois\Whois::query($domain);

use \Xeno\Net\Whois\Whois;

if(Whois::isRegistered($info) == $domain) {
	echo "$domain was registered\n";
	if(false === ($expiry = Whois::getExpiryDate($info))) {
		echo "expiry date not found\n";
	} else {
		echo 'expiry date: ', $expiry, "\n";
	}
} else {
	echo "$domain not found\n";
}