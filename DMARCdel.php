<?php

require_once('function.php');
$system = parse_ini_file('system.conf', true);
$ns = parse_ini_file('ns.conf',true);
$user = username();
openlog($system['syslog']['tag'], LOG_PID, $system['syslog']['fac']);

if (isset($_POST['domain'])) {
	$domain = $_POST['domain'];
	unset($_POST['domain']);
}


if ( isset($_POST['deldom']) AND filter_var($_POST['deldom'], FILTER_VALIDATE_BOOLEAN) ) 
	/* Remove SPF for $domain at all */

if ( updateRecord ( '_dmarc.' . $domain, $prev_record, NULL, 'DMARC', $ns['nsupdate'], $err ) ) {
        print '<p><img src="checked.gif"> Delete of DMARC record for ' . $domain . ' terminated successfully.</p>';

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
                                        else    printf('<p><img src="unchecked.gif"> DMARC REPORT record for %s removed with troubles.</p>',
                                                htmlentities("<$domain>"));
                        }
                }
                else
                        if ($uriPrevrecs === FALSE)
                                print '<p><img src="unchecked.gif"> Errors extracting previous uri records.</p>';
                print '<em> Ending activity on <b>old</b> uri.</em></div>';
        }
}
else
        print '<p><img src="unchecked.gif"> Delete of DMARC record for ' . $domain . ' ended with troubles. Check the errors returned.</p>';

closelog();
?>
