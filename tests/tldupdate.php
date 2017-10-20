<?php

chdir(__DIR__);
include_once '../vendor/autoload.php';

\Xeno\Net\Whois\Tld::update();

// update tld.json.gz example
\Xeno\Net\Whois\Tld::addServer('ad', 'whois.ripe.net');