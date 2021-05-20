<?php
require_once('function.php');
$ldap = parse_ini_file("ldap.conf", true);
$dkim = parse_ini_file('dkim.conf', true);
$selclass = $dkim['selector']['class'];
$seltag = $dkim['scheme']['period'];
$date = new DateTime('now');
switch ($seltag) {
        case 'M':
                $range = '1 month';
                break;
        case 'W':
                $range = '1 week';
                break;
        case 'Y':
                $range = '1 year';
                break;
        default:
                exit ("<p>Check your conf: the Selector's range of validity is wrong.</p>");
}
$interval = date_interval_create_from_date_string($range);
?>
<html>
<head>
<meta http-equiv="Content-Language" content="en">
<title>DMARC Assistant</title>
<meta charset="UTF-8">
<link rel="icon" href="https://dmarc.org//favicon.ico" />
<link rel="stylesheet" type="text/css" href="/include/style.css">
<script  src="/include/ajaxsbmt.js" type="text/javascript"></script>
<!--Load the Ajax API-->
<base target="_blank">
</head>
<body>
<h1>DMARC Assistant</h1>
<p style="float: right"><a href="setup.php">Info</a></p>
<?php
if ( strlen($dkim['selector']['separator']) != 1 )
	exit ("<p>The configured selector separator contains more than one char.</p>");
if ( $dkim['selector']['separator'] === '.' )
	exit ("<p>The configured selector separator is a dot.</p>");
if ( $dkim['selector']['separator'] === '_' ) 
        exit ("<p>The configured selector separator is a '_'.</p>");
?>
<form method="POST" name="QueryDef" action="list.php" onSubmit="xmlhttpPost('list.php', 'QueryDef', 'List', '<img src=\'/include/pleasewait.gif\'>', true); return false;">
<table style="float: left">
<?php
	printTableHeader('DMARC Query',array(NULL,NULL),TRUE,'Manage your Email Auth with DMARC, DKIM, SPF');
?>
<tr>
<td>Domain</td><td><input maxlength="255" value="" type="text" name="domain" placeholder="RFC5322.From domain"
                pattern="\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b"
                title="Look at your syntax. You must insert a FQDN domain name."
		required>
<input type="submit" 
       style="position: absolute; left: -9999px; width: 1px; height: 1px;"
       tabindex="-1" />
</td>
</tr>
<tr>
<td>DKIM Selector</td><td><select name="selclass" onChange="xmlhttpPost('list.php', 'QueryDef', 'List', '<img src=\'/include/pleasewait.gif\'>'); return false;">
<?php
foreach ( $selclass as $sel ) 
	print "<option value=\"$sel\">$sel</option>";
?>
</select>
</td>
</tr>
<tr>
<td>Op mode</td><td><select name="op" onChange="xmlhttpPost('list.php', 'QueryDef', 'List', '<img src=\'/include/pleasewait.gif\'>'); return false;"><option value="False" selected>Relaxed</option><option value="True">Strict</option></select>
</td>
</tr>
</table>
</form>
<div id="List" style="clear:left;"></div>
<h6>DMARC Assistant. HTML5 browser needed. Ver. <?php echo version(); ?></h6>
</body>
</html>
