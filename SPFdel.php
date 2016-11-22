<?php

require_once('function.php');
$system = parse_ini_file('system.conf', true);
$ns = parse_ini_file('ns.conf',true)['nsupdate'];
$user = username();
openlog($system['syslog']['tag'], LOG_PID, $system['syslog']['fac']);

if (isset($_POST['domain'])) {
	$domain = $_POST['domain'];
	unset($_POST['domain']);
}


if ( isset($_POST['deldom']) AND filter_var($_POST['deldom'], FILTER_VALIDATE_BOOLEAN) ) 
	/* Remove SPF for $domain at all */

if ( updateRecord ( $domain, $prev_record, NULL, 'SPF', $ns, $err ) ) 
        print '<p><img src="checked.gif"> Delete of SPF record for ' . $domain . ' terminated successfully.</p>';
else
        print '<p><img src="unchecked.gif"> Delete of SPF record for ' . $domain . ' ended with troubles. Check the errors returned.</p>';

closelog();
?>
