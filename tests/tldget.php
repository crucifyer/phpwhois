<?php

if(!isset($_SERVER['argv'][1])) exit;
chdir(__DIR__);
include_once '../vendor/autoload.php';

print_r(
	\Xeno\Net\Whois\Tld::getServer($_SERVER['argv'][1])
);