<?php

chdir(__DIR__);
include_once '../vendor/autoload.php';

// update tld.json.gz example
\Xeno\Net\Whois\Tld::addServer('co.nl', 'whois.co.nl');
\Xeno\Net\Whois\Tld::addServer('ac.uk', 'whois.ja.net');
\Xeno\Net\Whois\Tld::addServer('gov.uk', 'whois.ja.net');
foreach(['br', 'cn', 'eu', 'gb', 'hu', 'no', 'qc', 'sa', 'se', 'uk', 'us', 'uy', 'za'] as $d) {
	\Xeno\Net\Whois\Tld::addServer($d.'.com', 'whois.centralnic.com');
}
foreach(['gb', 'se', 'uk'] as $d) {
	\Xeno\Net\Whois\Tld::addServer($d.'.net', 'whois.centralnic.com');
}

// ipv6 not response servers
\Xeno\Net\Whois\Tld::addServer('kr', '49.8.14.101');
\Xeno\Net\Whois\Tld::addServer('best', '119.252.181.109');
