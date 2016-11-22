<?php

require_once('function.php');
$system = parse_ini_file('system.conf', true);
$ns = parse_ini_file('ns.conf',true)['nsupdate'];
$user = username();
$exit_err = NULL;
openlog($system['syslog']['tag'], LOG_PID, $system['syslog']['fac']);

if (isset($_POST['dom'])) {
	$domain = $_POST['dom'];
	unset($_POST['dom']);
}

/* Construct the record */
if ( isset($_POST['record']) ) $record = $_POST['record'];
else $record = makeSPFrecord($_POST,$err);

if ($record === FALSE) {
	syslog(LOG_ERR, $user.": $err. Exiting.");
	exit ('<p><img src="unchecked.gif"> Error building the SPF record:</p><pre>'.htmlentities($err).
               '</pre><p>If you are in trouble, please report this error to a sysadmin.</p>');
}

print "<p>Updating record SPF for: $domain - Value:</p><blockquote>".htmlentities($record).'</blockquote>';
syslog(LOG_INFO, "$user: Info: SPF: Updating SPF record for <$domain> with value <$record>...");

if ( updateRecord ( $domain, $prev_record, $record, 'SPF', $ns, $err ) ) 
        print '<p><img src="checked.gif"> Update of SPF record for ' . $domain . ' terminated successfully.</p>';
else
        print '<p><img src="unchecked.gif"> Update of SPF record for ' . $domain . ' ended with troubles. Check the errors returned.</p>';

closelog();
?>
