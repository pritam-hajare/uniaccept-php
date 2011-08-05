<?php

/**

Universal Acceptance of TLDs

Copyright (c) 2011 CentralNic. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of ICANN nor the names of its contributors may be
      used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY ICANN AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ICANN OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

require 'Net/DNS.php';

class Net_DNS_TLDVerify {

	/**
	* verify that a given label really is a TLD
	* @param string $tld the Top-Level Domain label
	* @return boolean
	*/
	static function verifyTLD($tld) {
		$resolver = new Net_DNS_Resolver;
		$answer = $resolver->query(self::stripTLD($tld), 'SOA');
		return ($answer && $answer->header->rcode != 'NXDOMAIN');
	}

	/**
	* remove unwanted characters from the label
	* @param string $tld the Top-Level Domain label
	* @return string
	*/
	static function stripTLD($tld) {
		return preg_replace('/.*\./', '', preg_replace('/\.$/', '', $tld));
	}

	/**
	* verify that a given label really is a TLD using an offline database
	* @param string $tld the Top-Level Domain label
	* @param string $file
	* @return boolean
	*/
	static function verifyTLDOffline($tld, $file='/tmp/tlds-alpha-by-domain.txt') {
		return in_array(self::stripTLD(strToUpper($tld)), explode("\n", trim(file_get_contents($file))));
	}

	/**
	* update the offline database
	* @param string $file
	* @return boolean
	*/
	static function refreshTLDDB($file='/tmp/tlds-alpha-by-domain.txt') {
		$tld_list = file_get_contents('http://data.iana.org/TLD/tlds-alpha-by-domain.txt');
		$tld_md5  = file_get_contents('http://data.iana.org/TLD/tlds-alpha-by-domain.txt.md5');

		// the MD5 check seems redundant: if obtained over TCP,
		// the TLD list cannot be corrupted, and any attacker
		// that can modify the TLD list can also modify the
		// checksum, as they come from the same source. Oh well.
		if (substr($tld_md5, 0, 32) == md5($tld_list)) {
			$temp_file = tempnam(dirname($file), __METHOD__);
			return (file_put_contents($temp_file, $tld_list) && rename($temp_file, $file));

		} else {
			return false;

		}
	}
}
