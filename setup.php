<?php
require_once('function.php');
$ldap = parse_ini_file("ldap.conf", true);
$dkim = parse_ini_file('dkim.conf', true);
$sys = parse_ini_file('system.conf', true);

openlog($sys['syslog']['tag'], LOG_PID, $sys['syslog']['fac']);

/* Environment */
$httpd_ver = $_SERVER['SERVER_SOFTWARE'];
$ssl = ( empty( $_SERVER['HTTPS'] ) ) ? '<img src="unchecked.gif"> SSL not present' : '<img src="checked.gif">SSL Ok'; 
if ( empty( $_SERVER['HTTPS'] ) )
	$ssl_comment = 'You have to enable SSL on your server. Otherwise the setup could work, but require authentication without SSL layer is a bad idea!';
	else	$ssl_comment = "SSL: {$_SERVER['SSL_VERSION_INTERFACE']}\r\nProtocol: {$_SERVER['SSL_PROTOCOL']}\r\nCertificate: {$_SERVER['SSL_SERVER_I_DN_CN']}\r\nCertificate Expiration: {$_SERVER['SSL_SERVER_V_END']}" ;

exec ('export COMPOSER_HOME=/root/.composer; /usr/bin/composer show jeremykendall/php-domain-parser', $domainparser, $dpstatus);
$dpstatus = ( $dpstatus ) ? '<img src="unchecked.gif"> Domain Parser not found' : '<img src="checked.gif"> Domain Parser found';

if ( isset($_SERVER['PHP_AUTH_USER']) )
	$user = '<img src="checked.gif"> Authenticated with user '.htmlentities('<'.$_SERVER['PHP_AUTH_USER'].'>');
else	$user = '<img src="unchecked.gif"> This session is not authenticated. Enable authentication!';

$timeZone = (date_default_timezone_get()) ? '<img src="checked.gif"> Date Timezone: '.date_default_timezone_get() : '<img src="unchecked.gif"> Date Timezone: <b>None</b>';

$ns = (file_exists('/usr/bin/nsupdate')) ?	'<img src="checked.gif"> nsupdate is present in /usr/bin' :
						'<img src="unchecked.gif"> nsupdate not founf in /usr/bin. Maybe is not present, or create a link to /usr/bin';

exec ('opendkim -V',$od, $odstatus);
$odstatus = ( $odstatus ) ? '<img src="unchecked.gif"> OpenDKIM not found' : '<img src="checked.gif"> OpenDKIM found';
$gk = (file_exists($sys['path']['genkey'])) ?	'<img src="checked.gif"> OpenDKIM-genkey found' :
						'<img src="unchecked.gif"> OpenDKIM-genkey not found. Check the value in system.conf (genkey).';

/* DKIM */
// LDAP conn
if (! isset($ldap['server']['port']) ) $ldap['server']['port'] = 389;
$ldapconn = conn_ldap($ldap['server']['host'], $ldap['server']['port'],$ldap['server']['user'],$ldap['server']['pwd']);
if ($ldapconn) {
	$ldapstatus = '<img src="checked.gif"> LDAP Successfully binded to '. $ldap['server']['host'].':'.$ldap['server']['port'];
	$dkimRequireForLDAP = TRUE;
}
else {
	$ldapstatus = '<img src="unchecked.gif"> Unable to bind to LDAP server '.$ldap['server']['host'];
	$ldap_comment = sprintf('Errors:<pre>%s</pre>',$ldap['server']['host'],htmlentities($err));
	$dkimRequireForLDAP = FALSE;
}

//Check selclass tree
foreach ($dkim['selector']['class'] as $selclass) {
	if ( is_tree ($ldapconn, "ou=$selclass".','.$ldap['server']['baseDN'], 'ou', $selclass) ) {
		$dkim["$selclass"]['status'] = sprintf('<img src="checked.gif"> The LDAP tree for %s is present in your LDAP server',$selclass);
		$dkim["$selclass"]['conf'] = sprintf('SigningTable ldap://%s:%d/ou=%s,%s?DKIMSelector,DKIMIdentity?sub?(&(|(mail=$d)(mailAlternateAddress=$d))(objectclass=inetLocalMailRecipient)(DKIMSelector=*))',$ldap['server']['host'],$ldap['server']['port'],$selclass,$ldap['server']['baseDN']);
		$dkim["$selclass"]['conf'] .= "\r\n".sprintf('KeyTable ldap://%s:%d/ou=%s,%s?DKIMDomain,DKIMSelector,DKIMKey?sub?(&(DKIMSelector=$d)(DKIMDomain=*)(DKIMKey=*))',$ldap['server']['host'],$ldap['server']['port'],$selclass,$ldap['server']['baseDN']);
	}
	else	{
		$dkim['status']["$selclass"] = sprintf('<img src="unchecked.gif"> The LDAP tree for %s is not present in your LDAP server. You must add it by hand, sorry.',$selclass);
		if ( $dkimRequireForLDAP ) $dkimRequireForLDAP = FALSE;
	}
}

$del_drv = array_search(TRUE, $dkim['delay driver']);
if ( $del_drv == 'mysql' ) {
	$db = parse_ini_file('db.conf', true);
	if (! isset($db['port']) ) $db['port'] = ini_get("mysqli.default_port");
	$mysql = mysqlconn($db['host'], $db['user'], $db['pass'], $db['name'], $db['port'], $err);
	if ( $mysql ) 
		$delaydrv_comment = sprintf('<img src="checked.gif"> Mysql connection to %s on DB <q>%s</q> is OK',$db['host'], $db['name']);
	else	$delaydrv_comment = '<img src="unchecked.gif"> Mysql connection unavailable. Errors:<pre>'.htmlentities($err).'</pre>';
	$mysql->close();
}

if ( $del_drv == 'ldap' ) {
	if ( is_tree ($ldapconn, $ldap['delaydel']['delayDN'], 'o') ) 
		$delaydrv_comment = sprintf('<img src="checked.gif"> The delay DB is correctly configured to <q>%s</q> on LDAP server %s',
			$ldap['delaydel']['delayDN'], $ldap['server']['host'].':'.$ldap['server']['port']);
	else	$delaydrv_comment = sprintf('<img src="unchecked.gif"> I can\'t find base dn <q>%s</q> on LDAP server %s. Delay DB not correctly configured.',
			$ldap['delaydel']['delayDN'], $ldap['server']['host'].':'.$ldap['server']['port']);
}
	

/* PHP Version */
if (version_compare(PHP_VERSION, '7.0.0') < 0)
        $phpVer_comment = '<img src="warning.gif">Your PHP version is very old. Hint: upgrade to minimum version 7 or higher.';
else	$phpVer_comment = '<img src="checked.gif">Your PHP version is optimal.';


?>
<html>
<head>
<meta http-equiv="Content-Language" content="en">
<title>SETUP Assistant for DMARC Assistant</title>
<meta charset="UTF-8">
<link rel="icon" href="favicon.ico" />
<link rel="stylesheet" type="text/css" href="/include/style.css">
<base target="_blank">
</head>
<body>
<h1>SETUP Assistant for DMARC Assistant</h1>
<p>This is not a configurator for DMARC Assistant. You must first configure your system as needed. Then go to this helper page, to find out any problems. The installation could be really good only when you will not see any <q><img src="unchecked.gif"></q> mark.<br /> Anyway, even if no <q><img src="unchecked.gif"></q> mark appears, we can't be sure that you haven't made any mistake in your conf. Good luck!</p>
<h2>System</h2>
<div id="content">
<p>HTTPD Version: <b><?php echo strip_tags($httpd_ver); ?></b></p>
<p><?php echo $ssl?></p>
<?php
if (! is_null($ssl_comment) )
	print "<pre>$ssl_comment</pre>";
?>
<p><?php echo $ns ?></p>
</div>
<h3>PHP</h3>
<div id="content">
<p>PHP Version: <b><?php echo PHP_VERSION ?></b></p>
<p><?php echo $phpVer_comment ?></p>
<p><?php echo $timeZone ?></p>
<p><?php echo $dpstatus; ?></p>
<pre><?php if ( is_array($domainparser) )
		foreach ( $domainparser as $row ) print $row."\r\n"; ?></pre>
<p><b><?php echo $user ?></b></p>
</div>

<h2>DKIM</h2>
<div id="content">
<p><?php echo $odstatus; ?></p>
<pre><?php if ( is_array($od) )
		foreach ( $od as $row ) print $row."\r\n"; ?></pre>
<p><?php echo $gk ?></p>
<p><?php echo $ldapstatus; ?></p>
<?php if ( isset($ldap_comment) ) echo "<p>$ldap_comment</p>"; ?>
<h3>Selector Class</h3>
<?php
foreach ($dkim['selector']['class'] as $selclass) {
	print "<h4>$selclass</h4>";
	print '<p>'.$dkim["$selclass"]['status'].'</p>';
	print '<p>For the servers running this selector class you must add the following configuration: <pre>'.htmlentities($dkim["$selclass"]['conf']).
		'</pre>';
}
print '<hr>';

/* Domains with active DKIM setup */
if ( $dkimRequireForLDAP ) {
	print '<p>Your DKIM setup is complete. You can configure domains for DKIM sign your email.</p><h3>Domains already signing</h3><p>I try to show a list of domains already signing.</p>';
	$IsThereAnybodyOutThere = FALSE;
        foreach ($dkim['selector']['class'] as $selclass) {
                $domains = listdom($ldapconn,$ldap['server']['baseDN'], $selclass);
		if ( count($domains) == 0 ) continue;
		else
			if (!$IsThereAnybodyOutThere)
				$IsThereAnybodyOutThere = TRUE;
                $title = "$selclass domains with DKIM setup";
                $footer = 'Found '.count($domains).' domains';
                print '<table>';
                printTableHeader($title,array('DKIM domain', 'Selector'),TRUE,$footer);
                print '<tbody>';
                foreach ($domains as $dom)
                        print '<tr><td>'.$dom.'</td><td>'.
                        getPrivSel ($ldapconn, $ldap['server']['baseDN'], $dom, $selclass, 'DKIMSelector', $err) ?: $err.
                        '</td></tr>';
                print '</tbody></table>';
        }
	if ( !$IsThereAnybodyOutThere ) print '<p><b>No signing domains found.</b></p>';
}
else {
	/* Some hints to setup your DKIM */
	print <<<END
	<p>It seems that your DKIM LDAP environment is only partly configured, or it is not configured at all.</p>
	<p>To setup DKIm you must first extend the LDAP schema with the following <a href="doc/96opendkim.ldif">schema file</a>.</p>
	<p>Then, you can create a new db, and initialize it with the following <a href="doc/dkim_initialize.ldif">LDIF file</a>.</p>
	<p>The initialize file is preconfigured with the following value:
	<ul><li>baseDN: o=dkim<ul>
		<li>You have: <b>{$ldap['server']['baseDN']}</b></li></ul></li>
	<li>Admin user: uid=dkimadmin,o=dkim<ul>
                <li>You have: <b>{$ldap['server']['user']}</b></li></ul></li>
	<li>Admin password: admin<ul>
                <li>You have: <b>{$ldap['server']['pwd']}</b></li></ul></li>
	<li>Selector class:<ul>
END;
	foreach ($dkim['selector']['class'] as $selclass) print "<li>$selclass</li>";
	print '</ul></li></ul><p>Please, change the LDIF file accordingly to your config, if it is needed.</p>';
}

?>
<h3>Delay Driver</h3>
<p>Delay driver chosen: <b><?php echo $del_drv; ?></b></p>
<p><b><?php echo $delaydrv_comment; ?></b></p>

<h3> Selector Hashing algorithms</h3>
<?php
$all_algo = hash_algos();
print "<p>Selector hash selected: <b>{$dkim['selector']['hash']}</b></p>";
$okhash = (in_array($dkim['selector']['hash'], $all_algo)) ? '<img src="checked.gif"> <q>'.$dkim['selector']['hash'].'</q> is supported.</p>' :
	'<img src="unchecked.gif"> <q>'.$dkim['selector']['hash'].'</q> is not supported.</p>';
print $okhash;
print '<p>Hint: always choose a short hash. List of supported algorithms:</p><ul>';
foreach ( $all_algo as $hash ) 
	print "<li>$hash</li>";
print '</ul>';
?>
</div>



<h6>DMARC Assistant. HTML5 browser needed. Ver. <?php echo version(); ?></h6>
</body>
</html>
