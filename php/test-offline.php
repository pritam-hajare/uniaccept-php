#!/usr/bin/php
<?php

require 'Net/DNS/TLDVerify.php';

$file = '/tmp/tld-list.txt';
if (!file_exists($file) || time() - filemtime($file) > 86400) Net_DNS_TLDVerify::refreshTLDDB($file);

if (empty($argv[1])) {
	print "Usage: {$argv[0]} [domain]\n";
	exit(2);

} else {
	if (Net_DNS_TLDVerify::verifyTLDOffline($argv[1], $file)) {
            print "{$argv[1]} contains a valid TLD\n";
            exit(0);

	} else {
            print "{$argv[1]} does not contain a valid TLD\n";
            exit(1);

	}
}
