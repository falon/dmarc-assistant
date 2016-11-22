<?php

require_once('function.php');
$ldap = parse_ini_file("ldap.conf", true);
$system = parse_ini_file('system.conf', true);
$ldapconf=$ldap['server'];
if (! isset($ldapconf['port']) ) $ldapconf['port'] = 389;

openlog($system['syslog']['tag'], LOG_PID, $system['syslog']['fac']);

// connect
$ldapconn = conn_ldap($ldapconf['host'], $ldapconf['port'],$ldapconf['user'],$ldapconf['pwd']);
if (!$ldapconn) {
	$err = 'Program terminated to prevent damage on your DKIM setup.';
        syslog(LOG_ERR, username().': Error: '.$err);
        exit($err);
}


if ( isset($_POST['deldom']) AND filter_var($_POST['deldom'], FILTER_VALIDATE_BOOLEAN) ) {
	/* Remove DKIM for a domain@selector at all */
	$dn = 'ou='.$_POST['domain'].',ou='.$_POST['selclass'].','.$ldapconf['baseDN'];
	if ( del_ldap($ldapconn,$dn,$err,TRUE) )
		print ('<p><img src="checked.gif"> LDAP DKIM privkey and all SignPaths on <i>'.$_POST['domain'].'</i> for <i>'.
		$_POST['selclass'].'</i> removed successfully.<br /><pre>'.htmlentities($err).'</pre></p>');
	else exit ('<p><img src="unchecked.gif"> Error in LDAP del: <pre>'.htmlentities($err).'</pre> If you are in trouble, please report this error to a sysadmin.</p>');

	$drv_del = array_search(TRUE, parse_ini_file('dkim.conf', true)['delay driver']);
	if ( remove_dkim_dns($drv_del,$ldapconn,$ldap['delaydel']['delayDN'],$_POST['domain'], $_POST['sel'],$err) )
		print ('<p><img src="checked.gif"> DKIM pubkey on <i>'.$_POST['domain'].'</i> for <i>'.
                $_POST['selclass'].'</i> with selector <i>'.$_POST['sel']. '</i> marked for delayed delete with success.<br /><pre>'.htmlentities($err).'</pre></p>');
	else exit ('<p><img src="unchecked.gif"> Error in delay deleting for DNS pubkey: <pre>'.htmlentities($err).'</pre> If you are in trouble, please report this error to a sysadmin.</p>');

	exit ('<p><img src="checked.gif"> DKIM Delete on <i>'.$_POST['domain'].'</i> for <i>'.
                $_POST['selclass'].'</i> terminated successfully.</p>');
}


if ( isset($_POST['delsub']) AND filter_var($_POST['delsub'], FILTER_VALIDATE_BOOLEAN) )
        /* Remove DKIM LDAP SignPath for a SUB.domain@selector */
	if (!isset($_POST['subdomdn'])) exit ('<p><img src="unchecked.gif"> Please select at least one domain.</p>');
	else
		foreach ( $_POST['subdomdn'] as $dn )
        		if ( del_ldap($ldapconn,$dn,$err,TRUE) )
                		print ('<p><img src="checked.gif"> LDAP DKIM SignPath <i>'.$dn.'</i> in <i>'.
                		$_POST['selclass'].'</i> removed successfully.</p><pre>'.htmlentities($err).'</pre>');
        		else exit ('<p><img src="unchecked.gif"> Error in LDAP del: <pre>'.htmlentities($err).'</pre> If you are in trouble, please report this error to a sysadmin.</p>');


if ( isset($_POST['delmail']) AND filter_var($_POST['delmail'], FILTER_VALIDATE_BOOLEAN) )
        /* Remove DKIM LDAP SignPath for a SUB.domain@selector */
	if (!isset($_POST['maildn'])) exit ('<p><img src="unchecked.gif"> Please select at least one email address.</p>');
        else
		foreach ( $_POST['maildn'] as $dn )
        		if ( del_ldap($ldapconn,$dn,$err,FALSE) )
                		print ('<p><img src="checked.gif"> LDAP DKIM SignPath <i>'.$dn.'</i> in <i>'.
                		$_POST['selclass'].'</i> removed successfully.</p><pre>'.htmlentities($err).'</pre></p>');
        		else exit ('<p><img src="unchecked.gif"> Error in LDAP del: <pre>'.htmlentities($err).'</pre> If you are in trouble, please report this error to a sysadmin.</p>');

ldap_unbind($ldapconn);
closelog();
?>
