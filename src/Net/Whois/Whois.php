<?php

namespace Xeno\Net\Whois;

class Whois
{
	private static $tlds, $punycode;

	public static function query($domain) {
		if(!self::$punycode) self::$punycode = new \TrueBV\Punycode();
		$domain = self::$punycode->encode($domain);
		if(false === ($tldo = self::getTld($domain))) return false;
		if($tldo->whois == 'notfound') return false;
		$query = $domain;
		if(isset($tldo->option->left)) $query = $tldo->option->left.$query;
		if(isset($tldo->option->right)) $query .= $tldo->option->right;
		$fp = fsockopen($tldo->whois, 43, $errno, $errstr, 5);
		fwrite($fp, "$query\r\n");
		$result = '';
		while(false !== ($row = fgets($fp, 8192))) {
			$result .= $row;
		}
		return $result;
	}

	public static function getTld($domain) {
		if(!self::$tlds) self::$tlds = json_decode(file_get_contents('compress.zlib://'.__DIR__.'/tld.json.gz'));
		$tlds = explode('.', $domain);
		$tlds = array_slice($tlds, -2, 2);
		$tld = implode('.', $tlds);
		if(isset(self::$tlds->{$tld})) return self::$tlds->{$tld};
		if(2 == count($tlds) && isset(self::$tlds->{$tlds[1]})) return self::$tlds->{$tlds[1]};
		return false;
	}

	public static function isRegistered($infotext, $domain) {
		if(!self::$punycode) self::$punycode = new \TrueBV\Punycode();
		return preg_match('~(?:^[^a-z]*domain|domain name).*?\b(?:'.preg_quote(self::$punycode->encode($domain), '~').'|'.preg_quote(self::$punycode->decode($domain), '~').')$~im', $infotext) ? true : false;
	}

	public static function getExpiryTimestamp($infotext) {
		if (preg_match('~(?:expir|paid-till|connected\s*\().*?\b(\d[^\)\]\r\n]+)~i', $infotext, $matches)) {
			return strtotime(preg_replace('~^(\d+)\.\s*(\d+)\.\s*(\d+)\.?$~', '\1-\2-\3', $matches[1]));
		}
		return false;
	}

	public static function getExpiryDate($infotext) {
		if(false === ($time = self::getExpiryTimestamp($infotext))) return false;
		return date('Y-m-d', $time);
	}
}