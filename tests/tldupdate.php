<?php

chdir(__DIR__);
include_once '../vendor/autoload.php';

\Xeno\Net\Whois\Tld::update(isset($_SERVER['argv'][1]));
