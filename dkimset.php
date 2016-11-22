<?php

require_once('function.php');
$ldap = parse_ini_file("ldap.conf", true);
$ldapconf=$ldap['server'];
$system = parse_ini_file('system.conf', true);
$dkim = parse_ini_file('dkim.conf',true);
$ns = parse_ini_file('ns.conf',true);
if (! isset($ldapconf['port']) ) $ldapconf['port'] = 389;
if (! isset($_POST) ) exit(0);
// $POST['selector'] is <selclass><sep><hashtag>

openlog($system['syslog']['tag'], LOG_PID, $system['syslog']['fac']);

if ( isset( $_POST['addkey']) AND filter_var($_POST['addkey'], FILTER_VALIDATE_BOOLEAN) )
	$delay_drv = 'add';
else
	if ( isset( $_POST['modkey']) AND filter_var($_POST['modkey'],FILTER_VALIDATE_BOOLEAN) ) {
		if ( array_count_values($dkim['delay driver'])[TRUE] == 1 )
        		$delay_drv = array_search(TRUE, $dkim['delay driver']);
		else exit ( '<p><img src="unchecked.gif"> Error choosing delay driver. You must set one engine.</p>');
	}

// connect
$ldapconn = conn_ldap($ldapconf['host'], $ldapconf['port'],$ldapconf['user'],$ldapconf['pwd']);
if (!$ldapconn) {
        $err = 'Program terminated to prevent damage on your DKIM setup.';
        syslog(LOG_ERR, username().': Error: '.$err);
        exit($err);
}


// Key management
$selclass = getSelclass ($dkim['selector']['class'],$_POST['selector']);
if ( (isset( $_POST['modkey']) AND filter_var($_POST['modkey'],FILTER_VALIDATE_BOOLEAN)) OR
	(isset( $_POST['addkey']) AND filter_var($_POST['addkey'],FILTER_VALIDATE_BOOLEAN)) )

	switch ( renewkeys($ldapconn,$ldapconf['baseDN'], $ldap['delaydel']['delayDN'], $_POST['domain'],$_POST['selector'],
			$selclass,$dkim['genkey']['opt'],$ns['nsupdate'], $delay_drv, $system['path']['genkey'], $err) ) {
		case -5:
			syslog(LOG_ALERT, $username.': Alert: Program teminated to prevent damage on your DKIM setup');
                        exit ('<p><img src="unchecked.gif"> Error in MX record, no keys modified: <pre>'.htmlentities($err).'
                                </pre> If you are in trouble, please report this error to a sysadmin.</p>');
		case -1:
			syslog(LOG_ALERT, $username.': Alert: Program teminated to prevent damage on your DKIM setup');
			exit ('<p><img src="unchecked.gif"> Error in key files: <pre>'.htmlentities($err).'
				</pre> If you are in trouble, please report this error to a sysadmin.</p>');
                case -2:
                        syslog(LOG_ALERT, $username.': Alert: Program teminated to prevent damage on your DKIM setup');
                        exit ('<p><img src="unchecked.gif"> Error in DNS add: <pre>'.htmlentities($err).
                                '</pre> If you are in trouble, please report this error to a sysadmin.</p>');
		case -3:
			syslog(LOG_ALERT, $username.': Alert: Program teminated to prevent damage on your DKIM setup');
			exit ('<p><img src="unchecked.gif"> Error in LDAP write: <pre>'.htmlentities($err).
				'</pre> To make consistent your setup manually delete the orphan <b>'.$_POST['selector'].
				'.'.$_POST['domain'].'</b> pubKey record added just now!<br>'.
				'If you are in trouble, please report this error to a sysadmin.</p>');
		case -4:
			print ('<p><img src="warning.gif"> The keys have been renewed, but can\'t delayed delete the current DNS record!'.
				'<pre>'.htmlentities($err).'</pre> Please report this error to a sysadmin.</p>');
			break;
		case 0:
			print '<p><img src="checked.gif"> DKIM keys on <i>'.$_POST['domain'].
			'</i> updated successfully: <pre>'.htmlentities($err).'</pre></p>';
	}


if ( isset($_POST['addsubdom']) AND filter_var($_POST['addsubdom'], FILTER_VALIDATE_BOOLEAN) ) {
	if ( empty($_POST['subdom']) ) exit ('<p><img src="warning.gif"> You want to add a subdomain, but you don\'t specify it!</p>');
	/* Setup a new SigningPath tree on LDAP */
        if (!add_dkim_subdom_ldap($ldapconn,$ldapconf['baseDN'],$_POST['domain'],$_POST['subdom'],$_POST['selector'],
                        $selclass,$err))
                exit ('<p><img src="unchecked.gif"> Error in LDAP add: <pre>'.htmlentities($err).'</pre> If you are in trouble, please report this error to a sysadmin.</p>');
        else print '<p><img src="checked.gif"> DKIM LDAP subsetup for <i>'.$_POST['subdom'].'</i> terminated successfully.</p>';	
}

if ( isset($_POST['addemail']) AND filter_var($_POST['addemail'], FILTER_VALIDATE_BOOLEAN) ) {
        if ( empty($_POST['email']) ) exit ('<p><img src="warning.gif"> You want to add an email as AUID, but you don\'t specify it!</p>');
	if ( empty($_POST['alias']) ) $_POST['alias'] = NULL;
	if ( empty($_POST['gn']) OR empty($_POST['sn']) ) exit ('<p><img src="unchecked.gif"> You must specify Name and Surname of the identity.</p>');
        /* Setup a new SigningPath on LDAP */
        if (!add_dkim_email_ldap($ldapconn,$ldapconf['baseDN'],$_POST['domain'],$_POST['email'],$_POST['alias'],$_POST['gn'], $_POST['sn'],
		$_POST['selector'], $selclass, $err))
                exit ('<p><img src="unchecked.gif"> Error in LDAP add: <pre>'.htmlentities($err)
			.'</pre> If you are in trouble, please report this error to a sysadmin.</p>');
        else print '<p><img src="checked.gif"> DKIM LDAP email setup for <i>'.$_POST['email'].'</i> terminated successfully.</p>';
}

ldap_close($ldapconn);
closelog();
?>
