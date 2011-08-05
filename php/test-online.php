#!/usr/bin/php
<?php

require 'Net/DNS/TLDVerify.php';

if (empty($argv[1])) {
	print "Usage: {$argv[0]} [domain]\n";
	exit(2);

} else {
	if (Net_DNS_TLDVerify::verifyTLD($argv[1])) {
            print "{$argv[1]} contains a valid TLD\n";
            exit(0);

	} else {
            print "{$argv[1]} does not contain a valid TLD\n";
            exit(1);

	}
}
