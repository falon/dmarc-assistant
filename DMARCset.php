<?php

require_once('function.php');
$system = parse_ini_file('system.conf', true);
$ns = parse_ini_file('ns.conf',true);
$default = parse_ini_file('dmarc.conf', true);
$user = username();

openlog($system['syslog']['tag'], LOG_PID, $system['syslog']['fac']);

if (isset($_POST['dom'])) {
	$domain = $_POST['dom'];
	unset($_POST['dom']);
}

if (empty ($_POST['rua']) ) unset($_POST['rua']);
if (empty ($_POST['ruf']) ) unset($_POST['ruf']);

/* Construct the record */
if ( isset($_POST['record']) ) $record = $_POST['record'];
else $record = makeDMARCrecord($_POST, $default, $err);

if ($record === FALSE) {
	syslog(LOG_ERR, $user.": Error: $err. Exiting.");
	exit ('<p><img src="unchecked.gif"> Error building the DMARC record:</p><pre>'.htmlentities($err).
               '</pre><p>If you are in trouble, please report this error to a sysadmin.</p>');
}


/* Update DMARC record */
if ( updateRecord ( '_dmarc.' . $domain, $prev_record, $record, 'DMARC', $ns['nsupdate'], $err ) ) {
	print '<p><img src="checked.gif"> Update of DMARC record for ' . $domain . ' terminated successfully.</p>';

        /* Delete previous DMARC REPORT records */
	$tags = recordToArray($prev_record);
	if (! empty ( $tags ) ) {
        	if (isset($tags['rua']))
			$olduris['rua'] = explode(',',$tags['rua']);
        	if (isset($tags['ruf']))
			$olduris['ruf'] = explode(',',$tags['ruf']);
		print '<div id="content"><em> Starting activity on <b>old</b> uri...</em>';
        	if (! is_bool($uriPrevrecs = urirecords ($ns['ns'],$olduris,$domain)) ) {
			if (! empty($uriPrevrecs) )  {
                		foreach ( $uriPrevrecs as $uriPrevRecord ) 
                        		/* With this I only Delete old DMARC REPORT record */
                        		if ( updateRecord ( $uriPrevRecord, $_, NULL, 'DMARC', $ns['nsupdate'], $err ) )
						printf('<p><img src="checked.gif"> DMARC REPORT record for %s removed successfully or already not present.</p>',
						htmlentities("<$domain>"));
					else	printf('<p><img src="unchecked.gif"> DMARC REPORT record for %s removed with troubles.</p>',
                                                htmlentities("<$domain>"));
			}
		}
        	else
			if ($uriPrevrecs === FALSE)
                		print '<p><img src="unchecked.gif"> Errors extracting previous uri records.</p>';
		print '<em> Ending activity on <b>old</b> uri.</em></div>';
	}

	/* Update DMARC REPORT record */
	/* Examine new URI report */
	$uris= array();
	if (isset($_POST['rua']))
        	$uris['rua'] = explode(',',$_POST['rua']);
	if (isset($_POST['ruf']))
        	$uris['ruf'] = explode(',',$_POST['ruf']);
	print '<div id="content"><em> Starting activity on <b>new</b> uri...</em>';
	if (! is_bool($urirecs = urirecords ($ns['ns'],$uris,$domain)) ) {
		if (! empty($urirecs) )  {
        		foreach ( $urirecs as $urirec ) 
                		if ( updateRecord ( $urirec, $_, 'v=DMARC1', 'DMARC', $ns['nsupdate'], $err) )
                                                printf('<p><img src="checked.gif"> DMARC REPORT record for %s updated successfully.</p>',
                                                htmlentities("<$domain>"));
                                        else    printf('<p><img src="unchecked.gif"> Update of DMARC REPORT record for %s terminated with troubles.</p>',
                                                htmlentities("<$domain>"));
		}
	}
        else
		if ($urirecs === FALSE)
			print '<p><img src="unchecked.gif"> Errors extracting new uri records.</p>';
		print '<em> Ending activity on <b>new</b> uri.</em></div>';
}
else
	 print '<p><img src="unchecked.gif"> Update of DMARC record for ' . $domain . ' ended with troubles. Check the errors returned.</p>';

closelog();
?>
