<?php

namespace Xeno\Net\Whois;

class Tld
{
	private function __construct() {}

	public static function update() {
		$jsonfile = __DIR__.'/tld.json.gz';
		$tlds = preg_split('~\s+~s', strtolower(preg_replace('~#.*~', '', file_get_contents('http://data.iana.org/TLD/tlds-alpha-by-domain.txt'))), -1,PREG_SPLIT_NO_EMPTY);
		$whois = file_exists($jsonfile) ? json_decode(file_get_contents('compress.zlib://'.$jsonfile)) : (object)[];
		$errors = [];
		foreach($tlds as $tld) {
			if(isset($whois->{$tld})) {
				echo "duplicate $tld\n";
				continue;
			}
			$fp = fsockopen('tcp://whois.iana.org', 43, $errno, $errtxt, 5);
			fwrite($fp, "$tld\r\n");
			$text = '';
			while(false !== ($row = fgets($fp, 8192))) {
				$text .= $row;
			}
			if(!preg_match('~domain:~', $text)) {
				$errors[] = $tld;
				continue;
			}
			if(preg_match('~whois:\s*(.+)~', $text, $matches)) {
				$url = $matches[1];
			} else {
				$url = 'whois.nic.'.$tld;
				if(gethostbyname($url) == $url) {
					$whois->{$tld} = (object)['whois' => 'notfound'];
					file_put_contents('compress.zlib://'.$jsonfile, json_encode($whois));
					echo "notfound $tld\n";
					continue;
				}
			}
			$whois->{$tld} = (object)['whois' => $url];
			file_put_contents('compress.zlib://'.$jsonfile, json_encode($whois));
		}
		$whois->de->option = (object)['left' => '-T dn,ace '];
		$whois->jp->option = (object)['right' => '/e'];
		file_put_contents('compress.zlib://'.$jsonfile, json_encode($whois));
		if(count($errors)) {
			file_put_contents(__DIR__.'/tld.err', implode("\n", $errors));
		}
	}

	public static function addServer($tld, $whoisurl, $optionleft = null, $optionright = null) {
		$jsonfile = __DIR__.'/tld.json.gz';
		$whois = json_decode(file_get_contents('compress.zlib://'.$jsonfile));
		$whois->{$tld}->whois = $whoisurl;
		if($optionleft) {
			$whois->{$tld}->option->left = $optionleft;
		}
		if($optionright) {
			$whois->{$tld}->option->right = $optionright;
		}
		file_put_contents('compress.zlib://'.$jsonfile, json_encode($whois));
	}
}