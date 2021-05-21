<?php

require_once('function.php');
$dom = $_POST['domain'] ?: NULL;
$str_mode = filter_var($_POST['op'], FILTER_VALIDATE_BOOLEAN);
$domfound = $dom;
$dkim = parse_ini_file('dkim.conf', true);
$selclass = $_POST['selclass'] ?: FALSE;
$conf = parse_ini_file("ns.conf", true);
$ldap = parse_ini_file("ldap.conf", true);
$system = parse_ini_file('system.conf',true);
if (! isset($ldapconf['port']) ) $ldapconf['port'] = 389;
$own = FALSE;
$NOdmarc = FALSE;
$NOspf = TRUE;


openlog($system['syslog']['tag'], LOG_PID, $system['syslog']['fac']);
if (version_compare(PHP_VERSION, '7.0.0') < 0)
        syslog(LOG_ALERT, "Alert: Please upgrade to PHP 7.");
$ip = getenv('HTTP_CLIENT_IP')?:
getenv('HTTP_X_FORWARDED_FOR')?:
getenv('HTTP_X_FORWARDED')?:
getenv('HTTP_FORWARDED_FOR')?:
getenv('HTTP_FORWARDED')?:
getenv('REMOTE_ADDR');
syslog(LOG_INFO, "$username: Info: Starting user activity from IP $ip.");

if ( is_null($dom) ) exit ('<p><img src="unchecked.gif">Please, insert a valid domain.</p>');


/* DKIM */
$class = NULL;
if ($str_mode)
	print '<p><img src="warning.gif">You choose a strict operation mode. You are allowed to configure DKIM and DMARC for each subdomain and not only for Organizational domain. Please, take care about your setup.</p>';
	
print '<h2>DKIM</h2><div id="content">';
$own = is_own($dom, $conf['ns']);
$setup_opt = NULL;
if ( $own ) {
	// connect
	$ldapconn = conn_ldap($ldap['server']['host'], $ldap['server']['port'],$ldap['server']['user'],$ldap['server']['pwd']);
	if (!$ldapconn) {
        	$err = 'LDAP connection error. Program terminated to prevent damage on your DKIM setup.';
	        syslog(LOG_ERR, $username.': Error: '.$err);
	        exit('Unable to proceed: <pre>'.htmlentities($err).'/pre>');
	}

	/* Search the selector in KeyTable */
	if ( $sel = ldap_pardom_get_privSel($ldapconn, $ldap['server']['baseDN'], $domfound, $selclass, 'dkimSelector', $str_mode, $err) ) {
	        if ($domfound != $dom) {
			/* If I found a record I should be the maintainer, anyway I recheck the ownership */
			$class = ' class="shadow blink"'; //Formatting
                	$own = is_own($domfound, $conf['ns']);
			$subdom = strstr($dom,'.'.$domfound,TRUE);
			if ( is_tree ($ldapconn, "ou=$subdom,ou=SigningTable,ou=$domfound,ou=$selclass".','.$ldap['server']['baseDN'], 'dkimSelector', $sel) )
				print '<p><img src="checked.gif"> '.htmlentities("The parent SDID domain <$domfound> already signs for <$dom>.").'</p>';
			else
        	        	print '<p><img src="warning.gif"> '.htmlentities("The parent SDID domain <$domfound> could DKIM sign for <$dom>.").'</p>';
		}
                if (! dns_getMX ($domfound, $err) )
                        exit ('<p><img src="warning.gif">'.htmlentities("$err - It seems that the MX record of <$domfound> doesn't exist!").'</p>');
		print '<p><img src="checked.gif">'.htmlentities("Good, I found a selector <$sel> with associated private key for domain <$domfound>.").'</p>';
		/* Search if the selector found matches also in SigningTable */
		if ( is_tree ($ldapconn, "ou=SigningTable,ou=$domfound,ou=$selclass".','.$ldap['server']['baseDN'], 'dkimSelector', $sel) )
                                print '<p><img src="checked.gif">Good, the LDAP SigningTable exists and it is coherent.</p>';
                else    exit('<p><img src="unchecked.gif">The SigningTable is not present in LDAP or is not associated to the chosen selector. Setup damaged.</p>');
		if ( $dkimrecord = thisRecord($domfound,'DKIM',$sel) ) {
			print '<p><img src="checked.gif">'.htmlentities("Good, I found a public key for selector <$sel> and domain <$domfound>.").'</p>';
			if ( isCurrent($dkim, $sel, $selclass, $domfound) ) {
				$setup_opt = 'del';
				print '<p><img src="checked.gif">The selector is valid for current time slot.</p>';
				print '<p><img src="checked.gif"> <b>Congratulations!</b> Your setup is optimal.</p>';
			}
			else {
				if ( is_delayed($sel.'._domainkey.'.$domfound, array_search(TRUE, $dkim['delay driver']), $ldapconn) )
					exit ('<p><img src="unchecked.gif">'.
					htmlentities("Panic: the pubkey of <$domfound> is delayed deleted, but it seems associated to a valid privKey! Check at your setup and... good luck because you are in trouble!").'</p>');
				print '<p><img src="warning.gif"> Your setup is working, but the keys are quite old and should be renewed. You have to wait for the authomated renewal process to finish, or if you are in trouble proceed with manual renew.</p>';
				$setup_opt = 'renew';
				$sel = buildSel ($dkim, $selclass, $domfound);
			}
		}
		else exit( '<p><img src="unchecked.gif">'.htmlentities("Selector <$sel> has not pubkey record for <$domfound>. Setup damaged.").'</p>' );
	}
	else {
		/* Domain without DKIM, fresh setup needed */
		$domfound = $dom;
                if (! dns_getMX ($domfound, $err) )
                        exit ('<p><img src="unchecked.gif">'.htmlentities("$err - A valid MX domain is needed.").'</p>');
		$sel = buildSel ($dkim, $selclass, $domfound);
		print '<p><img src="warning.gif">No selector found. Selector proposed for current time slot: '.htmlentities("<$sel>").'</p>';
		/* check presence of spourious trees */
		if ( is_tree ($ldapconn, "ou=SigningTable,ou=$domfound,ou=$selclass".','.$ldap['server']['baseDN'], 'dkimSelector') )
			exit ('<p><img src="warning.gif"> '. htmlentities("A selector has found on orphan or misaligned <$selclass> SigningTable for <$domfound>. Setup damaged.").'</p>');
		if ( thisRecord($domfound,'DKIM',$sel) ) {
                        print '<p><img src="warning.gif">'.htmlentities("A public key for this time slot and <$domfound> already exists!").'</p>';
			if ( is_delayed($sel.'._domainkey.'.$domfound, array_search(TRUE, $dkim['delay driver']), $ldapconn) )
                                        print ('<p><img src="checked.gif">'.
                                        htmlentities("The public key is delayed deleted. Maybe you have deleted this domain recently. You must wait for complete key removal cycle.").'</p>' );
			else exit ('<p><img src="unchecked.gif">'.
                                        htmlentities("Panic: the pubkey of <$domfound> is NOT pending for delayed deletion, is active. This is an unlegit state. Check at your DKIM setup and correct any issue!").'</p>');
		}
		else $setup_opt = 'add';
		
		
		
	}

	syslog(LOG_INFO, "$username: Info: Domain entered: <$dom>; DKIM Domain suitable: <$domfound>.");		
        if ($own) {
		if (!is_null($setup_opt))
			printf('<h3>DKIM setup for %s<span%s>%s</span>%s</h3>',htmlentities('<'),$class,htmlentities($domfound),htmlentities('>') );
		if ( isset($dkimrecord) ) print '<blockquote>'.$dkimrecord.'</blockquote>';
		dkim_setup($ldapconn, $ldap,$dkim,$domfound,$selclass,$sel,$setup_opt);
        	print '<div id="DKIMResult"></div></div>';
	}
	else print '<p><img src="unchecked.gif">You are not a maintainer for the domain <'.$domfound.'. DKIM ignored.</p>';
}

else print '<p><img src="unchecked.gif">You are not a maintainer for this domain. DKIM ignored.</p>';



/* SPF */
print '<h2>SPF</h2>';
print '<div id="content">';
$record = readRecord($dom, 'SPF');
if ( $own ) print '<h3>'.htmlentities('SPF setup for <'.$dom.'>').'</h3>';
if ( (is_array($record)) and (count($record) > 1) ) {
	if ( $own ) {
		delete_record_form($dom,'SPF');
		print ('<p><img src="unchecked.gif">There are too many SPF record!! What have you done?! Oh damn...</p><div id=\'SPFresult\'></div>');
	}
}
else if ( $record !== FALSE ) {
        print '<p><img src="checked.gif">SPF record exists:</p><blockquote>'.htmlentities($record[0]).'</blockquote>';
        if ($own) {
		delete_record_form($dom,'SPF');
		if (!mod_spf($dom,$record[0],$system['SPF']['template'],$err)) printf ("<p><img src=\"unchecked.gif\">%s</p>",htmlspecialchars($err));
	}
}
if ( $record === FALSE ) {
        print '<p><img src="unchecked.gif"> SPF record not found. While DKIM and DMARC policies could be valid for subdomains, SPF must be configured for each subdomain. Maybe would you query a subdomain?</p>';
        if ( $own ) {
                $spf_might = $system['SPF']['def_record'];
                if (!mod_spf($dom, $spf_might, $system['SPF']['template'], $err))
			printf ("<p><img src=\"unchecked.gif\">%s</p>",htmlspecialchars($err));
        }
}
print '</div>';


/* DMARC */
$domfound = $dom;
$class = NULL;
print '<h2>DMARC</h2>';
print '<div id="content">';
if ( $dmarc = dns_pardom_get_record($domfound,'DMARC',$str_mode) ) {
	if ($domfound != $dom) 
		$class = ' class="shadow blink"'; //Formatting
}
else $domfound = $dom;
if (! is_null($class) )
	print '<p><img src="warning.gif"> '.htmlentities("The parent domain <$domfound> should DMARC apply to <$dom>.").'</p>';
if ( $own )
        printf('<h3>DMARC RFC7489 setup for %s<span %s>%s</span>%s</h3>',htmlentities('<'),$class,htmlentities($domfound),htmlentities('>'));

syslog(LOG_INFO, "$username: Info: Domain entered: <$dom>; DMARC Domain suitable: <$domfound>.");
if ( $dmarc ) {
	$own = is_own($domfound, $conf['ns']);
	if ( $own && ( count ($dmarc) > 1 ) ) {
		delete_record_form($domfound,'DMARC');
		print '<p><img src="unchecked.gif"> There are too many DMARC records!! What have you done?! Oh damn...</p><div id=\'DMARCresult\'></div>';
	}
	else {
		print '<p><img src="checked.gif">DMARC record exists:</p><blockquote>'.htmlentities($dmarc[0]).'</blockquote>';
		if ($own) {
			if ( !$str_mode AND preg_match('/adkim=s;/', $dmarc[0]) )
                                print '<p><img src="warning.gif"> You choose the setup mode <b>Relaxed</b>, but your DMARC record requires <b>Strict</b> DKIM alignment. You could experience many issue if you don\'t configure a signature for each subdomain. Hint: switch to <b>Relaxed</b> DKIM alignment.</p>';
			delete_record_form($domfound,'DMARC');
                	if (!mod_dmarc($domfound, $dmarc[0], $system['DMARC']['template'], $err))
                        	print '<pre><img src="warning.gif"> '. htmlentities($err). '</pre>';
		}
	}
}
else {
	print '<p><img src="unchecked.gif"> DMARC record not found.</p>';
	if ( $own ) {
		$dmarc_might = $system['DMARC']['def_record'];
		if (!mod_dmarc($domfound, $dmarc_might, $system['DMARC']['template'], $err))
			print '<pre><img src="warning.gif"> '. htmlentities($err). '</pre>';
	}
}
print '</div>';


closelog();

?>
