#!/usr/bin/php
<?php
 /** DKIM Timer to delete the old keys already delayed-deleted **/
 /* return 0 if no errors occur */

require_once(__DIR__.'/function.php');
$ldap = parse_ini_file(__DIR__.'/ldap.conf', true);
$system = parse_ini_file(__DIR__.'/system.conf', true);
$dkim = parse_ini_file(__DIR__.'/dkim.conf',true);
$ns = parse_ini_file(__DIR__.'/ns.conf',true);
$mysqlconf = parse_ini_file(__DIR__.'/db.conf', true);


if (! isset($ldapconf['port']) ) $ldapconf['port'] = 389;

openlog('DKIMAutoEraser', LOG_PID, $system['syslog']['fac']);

if ( array_count_values($dkim['delay driver'])[TRUE] == 1 )
        $delay_drv = array_search(TRUE, $dkim['delay driver']);
else {
	$err = 'Error choosing delay driver. You must set one engine.';
	syslog(LOG_ERR, username().": Error: $err");
	exit ( $err );
}

$dateDel = new DateTime($dkim['delay time']['interval']);


switch ( $delay_drv ) {
	case 'ldap':
		if ( $ret = ldap_deleteOldRecord($ldap, $ns['nsupdate'], $dateDel) )
			syslog(LOG_INFO, username().': Info: Program terminated successfully.');
		else syslog(LOG_ERR, username().': Error: Program terminated with troubles.');
		break;

	case 'mysql':
		if ( $ret = mysql_deleteOldRecord($mysqlconf, $ns['nsupdate'], $dateDel->format('Y-m-d H:i:s T')) )
                        syslog(LOG_INFO, username().': Info: Program terminated successfully.');
                else syslog(LOG_ERR, username().': Error: Program terminated with troubles.');
		break;

	default:
		syslog(LOG_ERR, username().": Error: Unknown driver <$delay_drv>. Exiting.");
		$ret = 0;
}
closelog();
exit ( (int) (!$ret) );
?>
