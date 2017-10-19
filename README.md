# php whois query library

```bash
$ php composer.phar require "crucifyer/phpwhois" "dev-master"
```

```php
$domain = 'github.com'; // not support subdomain.

$info = \Xeno\Net\Whois\Whois::query($domain);

use \Xeno\Net\Whois\Whois; // shortly

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
```