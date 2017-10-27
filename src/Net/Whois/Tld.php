<?php

namespace Xeno\Net\Whois;

class Tld
{
	private function __construct() {}

	public static function update($notfoundupdate = false) {
		$tlds = preg_split('~\s+~s', strtolower(preg_replace('~#.*~', '', file_get_contents('http://data.iana.org/TLD/tlds-alpha-by-domain.txt'))), -1,PREG_SPLIT_NO_EMPTY);
		$whois = self::loadJSON();
		$errors = [];
		foreach($tlds as $tld) {
			if(isset($whois->{$tld})) {
				if(!($notfoundupdate && 'notfound' == $whois->{$tld}->whois)) {
					echo "duplicate $tld\n";
					continue;
				}
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
					$url = $tld.'.whois-servers.net';
					if(gethostbyname($url) == $url) {
						$url = 'whois.'.$tld;
						if(gethostbyname($url) == $url) {
							$whois->{$tld} = (object)['whois' => 'notfound'];
							self::saveJSON($whois);
							echo "notfound $tld\n";
							continue;
						}
					}
				}
			}
			$whois->{$tld} = (object)['whois' => $url];
			self::saveJSON($whois);
			echo "update $url\n";
		}
		$whois->de->option = (object)['left' => '-T dn,ace '];
		$whois->jp->option = (object)['right' => '/e'];
		self::saveJSON($whois);
		if(count($errors)) {
			file_put_contents(__DIR__.'/tld.err', implode("\n", $errors));
		}
	}

	public static function addServer($tld, $whoisurl, $optionleft = null, $optionright = null) {
		$whois = self::loadJSON();
		$obj = (object)['whois' => $whoisurl];
		if($optionleft || $optionright) $obj->option = (object)[];
		if($optionleft) {
			$obj->option->left = $optionleft;
		}
		if($optionright) {
			$obj->option->right = $optionright;
		}
		$whois->{$tld} = $obj;
		self::saveJSON($whois);
	}

	public static function getServer($tld) {
		$whois = self::loadJSON();
		if(!isset($whois->{$tld})) return false;
		return $whois->{$tld};
	}

	private static function loadJSON() {
		$jsonfile = __DIR__.'/tld.json.gz';
		return file_exists($jsonfile) ? json_decode(file_get_contents('compress.zlib://'.$jsonfile)) : (object)[];
	}

	private static function saveJSON($obj) {
		file_put_contents('compress.zlib://'.__DIR__.'/tld.json.gz', json_encode($obj));
	}
}