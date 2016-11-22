#!/usr/bin/php
<?php
 /** DKIM Timer to renew the keys for existing domains **/
 /* Return 0 if no errors occur */

require_once(__DIR__.'/function.php');
$ldap = parse_ini_file(__DIR__."/ldap.conf", true);
$ldapconf=$ldap['server'];
$system = parse_ini_file(__DIR__.'/system.conf', true);
$dkim = parse_ini_file(__DIR__.'/dkim.conf',true);
$ns = parse_ini_file(__DIR__.'/ns.conf',true);

if (! isset($ldapconf['port']) ) $ldapconf['port'] = 389;

openlog('DKIMAutoUpdater', LOG_PID, $system['syslog']['fac']);

/* Wait for a while into time slot */
$seconds = rand ( 300, 3600 );
syslog(LOG_INFO, sprintf('%s: Info: waiting for %d minutes',$username, round($seconds/60, 1)) );
sleep ( $seconds );

if ( array_count_values($dkim['delay driver'])[TRUE] == 1 )
        $delay_drv = array_search(TRUE, $dkim['delay driver']);
else exit ( 'Error choosing delay driver. You must set one engine.' );


$ldapconn = conn_ldap($ldapconf['host'], $ldapconf['port'],$ldapconf['user'],$ldapconf['pwd']);
if (!$ldapconn) {
        $err = 'Program terminated to prevent damage on your DKIM setup.';
        syslog(LOG_ERR, $username.': Error: '.$err);
        exit($err);
}

foreach ($dkim['selector']['class'] as $selclass) {
	syslog(LOG_INFO, username().": Info: Starting renewal process for <$selclass> domains...");
	syslog(LOG_INFO, username().": Info: Starting Domains Discover for <$selclass>...");
	$domains = listdom($ldapconn,$ldapconf['baseDN'], $selclass);
	syslog(LOG_INFO, $username.': Info: Domains Discover found '.count($domains)." domains for <$selclass>.");
	$return = 0;
	foreach ($domains as $dom)
		switch ( $ret = renewkeys($ldapconn,$ldapconf['baseDN'],$ldap['delaydel']['delayDN'], $dom,
				$sel = buildSel ($dkim, $selclass, $dom),
                        	$selclass,$dkim['genkey']['opt'],$ns['nsupdate'], $delay_drv,
				$system['path']['genkey'], $err) )
		{
                	case -1:
                        	syslog(LOG_ALERT, "$username: The keys for <$dom> in <$selclass> doesn't have been renewed for error during keys generation!");
				$return = $ret;
				break;
                	case -2:
                        	syslog(LOG_ALERT, "$username: The keys for <$dom> in <$selclass> doesn't have been renewed for error during DNS MOD on pubKey!");
				$return = $ret;
				break;
                        case -3:
                                syslog(LOG_EMERG, "$username: The keys for <$dom> in <$selclass> doesn't have been renewed for error during LDAP MOD on privKey. To make consistent your setup manually delete the <$sel._domainkey.$dom> pubKey record added just now!");
				$return = $ret;
                                break;
                        case -4:
                                syslog(LOG_ALERT, "$username: The keys for <$dom> in <$selclass> have been renewed, but can't delayed delete the current DNS record!");
				$return = $ret;
                                break;
                	case 0:
                        	syslog(LOG_INFO, "$username: LDAP DKIM keys for <$dom> in <$selclass> renewed successfully.");
        	}
	syslog(LOG_INFO, $username.": Info: renewal process for <$selclass> domains terminated.");

}
syslog(LOG_INFO, "$username: Info: Keys renewal process terminated.");
ldap_unbind($ldapconn);
closelog();
exit ( $return );
?>
