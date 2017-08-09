<?php
ini_set('error_log', 'syslog');

function username() {
        if (isset ($_SERVER['REMOTE_USER'])) $user = $_SERVER['REMOTE_USER'];
                else if (isset ($_SERVER['USER'])) $user = $_SERVER['USER'];
		else if ( isset($_SERVER['PHP_AUTH_USER']) ) $user = $_SERVER['PHP_AUTH_USER'];
		else {
			syslog(LOG_ALERT, "No user given by connection from {$_SERVER['REMOTE_ADDR']}. Exiting");
    			exit(0);
		}
        return $user;
}
$username = username();

function addErrorReturn (&$err, $add, $fileA, $fileB) {
/* Only used in delayed delete to shortcut a sane return */
	$err .= "\n".$add;
	unlink($fileA);
	unlink($fileB);
	return -4;
}
	
function printTableHeader($title,$content,$footer=FALSE,$fcontent) {
        print <<<END
<caption>$title</caption>
<thead>
<tr>
END;
	$cols = count($content);
	for ($i=0; $i<$cols; $i++) 
		print '<th>'.$content[$i].'</th>';
	print '</tr></thead>';
	if ($footer) {
		print '<tfoot><tr>';
		print "<th colspan=\"$cols\">".$fcontent.'</th>';
        	print '</tr></tfoot>';
	}
	return TRUE;
}



function buildSel ($dkconf, $selclass, $dom) {
/* Build a selector in current time slot */
	if ( $dkconf['selector']['hash'] )
		return $selclass . $dkconf['selector']['separator'] .
			hash( $dkconf['selector']['hash'], hash( 'sha256', date( $dkconf['scheme']['period'] ). $dom ) );
	else
		return $selclass . $dkconf['selector']['separator'] . date( $dkconf['scheme']['period'] ) .
			strtr( $dom, '.', "\0" );
}




/* LDAP class */
  /* Low level LDAP Class */
function conn_ldap($host,$port,$user,$pwd) {
	$username = username();
	$ldapconn = ldap_connect($host, $port);
	ldap_set_option($ldapconn, LDAP_OPT_NETWORK_TIMEOUT, 5);
	if ($ldapconn) {
	        // binding to ldap server
	        syslog(LOG_INFO,  "$username: Info: LDAP: Successfully connected to $host:$port");
	        $ldapbind = ldap_bind($ldapconn, $user, $pwd);
	        // verify binding
	        if ($ldapbind) {
	                syslog(LOG_INFO,  "$username: Info: LDAP: Successfully BIND as <".$user.'>.');
			return $ldapconn;
		}
	        else {
	                $err = 'LDAP: Error trying to bind as <'.$user.'>: '.ldap_error($ldapconn);
	                syslog(LOG_ERR, "$username: Error: $err.");
			ldap_unbind($ldapconn);
	                return FALSE;
	        }
	}
	else {
	        $err = 'LDAP: Could not connect to LDAP server '.$host.':'.$port;
	        syslog(LOG_ERR, $username.": Error: $err.");
	        return FALSE;
	}
}



function getPrivSel ($ds, $basedn, $dom, $selclass, $selAttr, &$err) {
/* Read selector value from KeyTable. Return selector value or FALSE otherwise */
	$username = username();
	$selAttr = strtolower($selAttr);
	$dn = "ou=KeyTable,ou=$dom,ou=$selclass".','.$basedn;
	if ( $sr = @ldap_read($ds, $dn, "$selAttr=*", array("$selAttr")) ) {
		$info = ldap_get_entries($ds, $sr);
		ldap_free_result($sr);
		switch ( $info['count']  > 1 ? '2':$info['count'] ) {
			case 0:
				$err = "LDAP: <$selclass> selector for <$dom> does not exist.";
				syslog(LOG_ERR, "$username: Error: $err");
				return FALSE;
			case 1:
				$err = "LDAP: <$selclass> selector for <$dom> is <{$info[0]["$selAttr"][0]}>";
				syslog(LOG_INFO,"$username: Info: $err");
				return $info[0]["$selAttr"][0];
			case 2:
				$err = "LDAP: <$selclass> selector for <$dom> has {$info['count']} values! Setup broken, you must fix it.";
				syslog(LOG_ERR, "$username: Error: $err");
				return FALSE;
		}
	}
	$err = "LDAP: <$selclass> selector for <$dom> not found. Reason: ".ldap_error($ds);
	syslog(LOG_ERR, "$username: Info: $err");
	return FALSE;
}
			
		
		
function ldap_pardom_get_privSel ($ds, $basedn, &$dom, $selclass, $selAttr, $strictmode, &$err) {
/* Find selector on dom or parent dom of at least second level */
/* Return the selector and the associated domain, or FALSE and tld */
// $selector = <selclass><sep><hashtag>

        if (! ( $occurrence = strstr($dom, '.')) )
                return FALSE;
	if ( ($sel = getPrivSel ($ds, $basedn, $dom, $selclass, $selAttr, $error)) !== FALSE )
		return $sel;
        else
		$err .= $error."\n";
	if ( $dom == orgDom($dom) ) return FALSE;
	$dom = substr($occurrence,1);
	if ($strictmode) return FALSE;
	return ldap_pardom_get_privSel ($ds, $basedn, $dom, $selclass, $selAttr, $strictmode, $err);
}



function is_tree ($ds, $dn, $attrcheck, $value='*') {
	$attrcheck = strtolower($attrcheck);
	// I append '@' because dn could not exist and generate a warning
	if ( $sr = @ldap_read($ds, $dn, "$attrcheck=$value", array("$attrcheck")) ) {
		$info = ldap_get_entries($ds, $sr);
		ldap_free_result($sr);
		if ( ($value != '*')  and ($info['count'] > 0) )
			if ( $info[0]["$attrcheck"][0] == $value ) 
				return TRUE;
			else return FALSE;
		else	if ( $info['count'] > 0 )
				return TRUE;
	}
        return FALSE;
}



function del_ldap($ds,$dn,&$err,$recursive=false) {
	$username = username();
	if ($recursive)
		$errmore = 'and all its childs';
	else $errmore = NULL;
        $err = "LDAP: <$dn> $errmore deleted successfully";
        if (!ldap_delete_r($ds, $dn, $recursive)) {
                $err = "LDAP: Can't delete <$dn> $errmore: Reason: ".ldap_error($ds);
		syslog(LOG_ERR, $username.": Error: $err.");
                return FALSE;
        }
	syslog(LOG_INFO, $username.": Info: $err.");
        return TRUE;
}



function ldap_delete_r($ds,$dn,$recursive=false){
    if($recursive == false){
        return(ldap_delete($ds,$dn));
    }else{
        //searching for sub entries
	// See at search for CoS entries in RH Directory Server manual.
        $sr=ldap_list($ds,$dn,"(|(objectclass=*)(objectclass=ldapSubEntry))",array(""));
        $info = ldap_get_entries($ds, $sr);
        for($i=0;$i<$info['count'];$i++){
            //deleting recursively sub entries
            $result=ldap_delete_r($ds,$info[$i]['dn'],$recursive);
            if(!$result){
                //return result code, if delete fails
                return($result);
            }
        }
        return(ldap_delete($ds,$dn));
    }
}


function add_ldap ($ds, $dn, &$add,&$err) {
	$username = username();
        $err = "LDAP: <$dn> successfully added";
        if (!ldap_add($ds, $dn, $add)) {
                $err = "LDAP: Can't create <$dn>. Reason: ".ldap_error($ds);
                syslog(LOG_ERR, $username.": Error: $err.");
                return FALSE;
        }
        $add = array();
        syslog(LOG_INFO, $username.": Info: $err.");
        return TRUE;
}

function replace_ldap ($ds, $dn, &$entry, &$err) {
	$username = username();
        $err = "LDAP: <$dn> successfully modified";
        if (!ldap_mod_replace($ds, $dn, $entry)) {
                $err = "LDAP: Can't modify <$dn>. Reason: ".ldap_error($ds);
                syslog(LOG_ERR, $username.": Error: $err.");
                return FALSE;
        }
        $entry=array();
        syslog(LOG_INFO, $username.": Info: $err.");
        return TRUE;
}



  /* Middleware LDAP Class*/

function ldap_delayed_delete($ds,$base,$sel,$dom,&$err) {
        /* Insert old key in the delayed delete db */
	//$sel = <selclass><sep><hashtag>

        $oldDKIMrecord = $sel.'._domainkey.'.$dom;

	/* Prepare the data to add */
	$dn = "dc=$sel-$dom,$base";
	$info['objectClass'][0] = 'top';
	$info['objectClass'][1] = 'domain';
	$info['objectClass'][2] = 'dkimdelete';
	$info['objectClass'][3] = 'dkim';
	$info['dkimdomain'] = $dom;
	$info['dkimselector'] = $sel;
	$info['dkimrecord'] = $oldDKIMrecord;
	
	
        if ( add_ldap ($ds, $dn, $info, $err) )
                return TRUE;
        else
                return FALSE;

}



function ldap_isDelayedRecord($ds, $record, $ldapdelconf) {
/* Return  TRUE if the DNS record is in delayed deleted state */
        $user = username();
        /* Construct the query */
        $query = $ldapdelconf['delayATTR']."=$record";
        if  ( $sr = ldap_list($ds, $ldapdelconf['delayDN'], $query, array($ldapdelconf['delayATTR'])) ) {
                $c = ldap_count_entries($ds, $sr);
		ldap_free_result($sr);
		switch ($c  > 1 ? '2': $c) {
			case 0:
                                syslog(LOG_INFO, "$user: Info: LDAP: The record <$record> is currently active.");
                                break;
                        case 1:
				syslog(LOG_INFO, "$user: Info: LDAP: The record <$record> is delayed deleted.");
                                return TRUE;
                        case 2:
                                syslog(LOG_ERR, "$user: Error: LDAP: It seems that <$record> is duplicated in delayed DB.");
                                return FALSE;
                        default:
                                syslog(LOG_ERR, "$user: Error: LDAP: some error during query: unexpected result.");
                }
        }
        return FALSE;
}



function ldap_deleteOldRecord($ldapconf, $nsupdateconf, $createTimestamp) {
/* Delete entry based on her createTimestamp value */

	$username = username();
	$records = array();
	// connect
	$ds = conn_ldap($ldapconf['server']['host'], $ldapconf['server']['port'],$ldapconf['server']['user'],$ldapconf['server']['pwd']);
	if (!$ds) {
        	$err = 'Program terminated abnormally, no entries deleted.';
        	syslog(LOG_ERR, $username.': Error: '.$err);
        	return FALSE;
	}

	/* Construct the query */
        $myzone= $createTimestamp->getTimezone();
        $createTimestamp->setTimezone(new DateTimeZone('UCT'));
	$createTimestamp->format('YmdHis\Z');
	$query = '(&('.$ldapconf['delaydel']['delayATTR'].'=*)(createtimestamp<='.$createTimestamp->format('YmdHis\Z').'))';
	$createTimestamp->setTimezone($myzone);

	/* Looking for the record to delete */
        if  ( $sr = ldap_list($ds, $ldapconf['delaydel']['delayDN'], $query, array($ldapconf['delaydel']['delayATTR'])) ) {
        	$info = ldap_get_entries($ds, $sr);
        	if ( $info['count'] == 0 ) {
        		$err = 'LDAP: I haven\'t found any record to delete.';
                	syslog(LOG_WARNING, $username.": Warn: $err");
                	return TRUE;
		}
		$nr = 0;
        	for ($i = 0; $i < $info['count']; $i++) {
			if ($info[$i][$ldapconf['delaydel']['delayATTR']]['count'] != 1)
				syslog(LOG_WARNING, $username.': Warn: '.
				'Skipping <'.$info[$i]['dn'].'> because it seems to have '.
				$info[$i][$ldapconf['delaydel']['delayATTR']]['count'].' values of <'.
				$ldapconf['delaydel']['delayATTR'].'>.');
			else {
				$records['values'][] = $info[$i][$ldapconf['delaydel']['delayATTR']][0];
				$records['dn'][] = $info[$i]['dn'];
				$nr++;
			}
		}
        }
	else {
        	$err = 'LDAP: Error during search! Reason: '.ldap_error($ds);
        	syslog(LOG_ERR, $username.": Danger: $err.");
		return FALSE;
	}
	syslog (LOG_INFO, $username.": Info: $nr delayed deleted records found before ".$createTimestamp->format('Y-m-d H:i:s T').'.');

	/* Real delete */
	$ret = TRUE;
	$retL = FALSE;
	for ($i=0; $i<$nr; $i++) {
		if ( $retD = updatezone($nsupdateconf['name'], 'delete',
                array('dom' => $records['values'][$i], 'prereq' => "yxdomain {$records['values'][$i]}", 'type' => 'TXT'), '', $err) )
			if ( $retL = del_ldap($ds,$records['dn'][$i],$err) )
				syslog (LOG_INFO, $username.': Info: record <'. $records['values'][$i].'> deleted at all successfully.');
			else syslog(LOG_ERR, $username.': Error: <'. $records['values'][$i].'> deleted only from DNS and not from LDAP!');
		else syslog(LOG_ERR, $username.': Error: Can\'t delete <'.$records['values'][$i].'>.');
		$ret = $ret && $retD && $retL;
	}
	ldap_unbind($ds);
	/* Return operation status */
	return $ret;
}



function add_dkim_ldap($ds, $base, $dom, $sel, $selclass, $key, &$err) {
        /* Add tree and key for a new domain */
	// $sel = <selclass><sep><hashtag>
        /* Prepare the data to add */

        /* OU root Container */
        $dn = "ou=$dom,ou=$selclass,$base";
        $info['objectClass'][0] = 'top';
        $info['objectClass'][1] = 'organizationalunit';
        $info['ou'] = $dom;
        if (!add_ldap ($ds, $dn, $info, $err)) return FALSE;

        /* CoS Template for the domain */
        $dnT = "cn=CosTemplate_DKIMSelector,ou=$dom,ou=$selclass,$base";
        $info['cn'] = 'CosTemplate_DKIMSelector';
        $info['DKIMSelector'] = $sel;
        $info['cosPriority'] = 0;
        $info['objectClass'][0] = 'top';
        $info['objectClass'][1] = 'costemplate';
        $info['objectClass'][2] = 'ldapsubentry';
        $info['objectClass'][3] = 'extensibleobject';
        if (!add_ldap ($ds, $dnT, $info, $err)) return FALSE;

        /* CoS for the domain */
        $dn = "cn=$selclass CoS,ou=$dom,ou=$selclass,$base";
        $info['objectClass'][0] = 'top';
        $info['objectClass'][1] = 'ldapsubentry';
        $info['objectClass'][2] = 'cossuperdefinition';
        $info['objectClass'][3] = 'cosPointerDefinition';
        $info['cn'] = "$selclass CoS";
        $info['costemplatedn'] = $dnT;
        $info['cosAttribute'] = 'dkimselector override';
        $info['description'] = "CoS to force DKIMSelector to $selclass type";
        if (!add_ldap ($ds, $dn, $info, $err)) return FALSE;

        /* Keytable */
        $dn = "ou=KeyTable,ou=$dom,ou=$selclass,$base";
        $info['DKIMDomain'] = $dom;
        $info['DKIMSelector'] = $sel;
        $info['objectClass'][0] = 'top';
        $info['objectClass'][1] = 'organizationalunit';
        $info['objectClass'][2] = 'dkim';
        $info['ou'] = 'KeyTable';
        $info['DKIMKey'] = $key;
        if (!add_ldap ($ds, $dn, $info, $err)) return FALSE;

        /* SigningTable */
        $dn = "ou=SigningTable,ou=$dom,ou=$selclass,$base";
        $info['DKIMIdentity'] = '@'.$dom;
        $info['mail'] = $dom;
        $info['DKIMSelector'] = $sel;
        $info['objectClass'][0] = 'top';
        $info['objectClass'][1] = 'organizationalunit';
        $info['objectClass'][2] = 'dkim';
        $info['objectClass'][3] = 'dkimmailrecipient';
        $info['ou'] = 'SigningTable';
        if (! add_ldap ($ds, $dn, $info, $err) ) return FALSE;

        syslog(LOG_INFO, username()." Info: LDAP: The new domain <$dom> has added to DKIM for <$sel>.");
        return TRUE;
}



function mod_dkim_ldap($ds, $base, $dom, $sel, $curSel, $selclass, $key, &$err) {
        /* Modify Selector and privKey for an existing domain */
	// $sel = <selclass><sep><hashtag>
	$username = username();

        /* CoS Selector */
        if ( !$curSel ) return FALSE;
        if ( $curSel === $sel ) {
                $err = "LDAP: The current selector is already <$sel>. I can't change key of existing selector.";
                syslog(LOG_ERR, $username." Info: $err");
                return  FALSE;
        }
        $entry['DKIMSelector'][0] = $sel;
        /* Change Selector value */
	$dnT = "cn=CosTemplate_DKIMSelector,ou=$dom,ou=$selclass,$base";
        if (!replace_ldap ($ds, $dnT, $entry, $err)) return FALSE;
        /* Change privKey */
        $dn = "ou=KeyTable,ou=$dom,ou=$selclass,$base";
        $entry['DKIMKey'] = $key;
        if ( replace_ldap ($ds, $dn, $entry, $err) ) {
                $err = "LDAP: The current DKIMSelector of value <$curSel> has been replaced with the value <$sel>.";
                syslog(LOG_INFO, $username." Info: $err");
                	return TRUE;
        }
        return FALSE;
}



function add_dkim_subdom_ldap($ds, $base, $dom, $subdom, $sel, $selclass, &$err) {
        /* Add signing path for a new domain */
	// $sel = <selclass><sep><hashtag>
	$username = username();
        if ( strpos($subdom,$dom) === FALSE ) {
                $err = "LDAP: You try to add <$subdom> which is not a subdomain of <$dom>";
                syslog(LOG_ERR, $username." Info: $err");
                return FALSE;
        }

	if (! dns_getMX ($subdom, $err)) 
                return FALSE;

        /* Prepare the data to add */

        $ou = substr($subdom, 0, strrpos($subdom,'.'.$dom));

        /* OU main Container */
        $dn = "ou=$ou,ou=SigningTable,ou=$dom,ou=$selclass,$base";
        $info['DKIMIdentity'] = '@'.$subdom;
        $info['mail'] = $subdom;
        $info['ou'][0] = $ou;
        #$info['ou'][1] = $subdom;
        $info['objectClass'][0] = 'top';
        $info['objectClass'][1] = 'organizationalunit';
        $info['objectClass'][2] = 'dkim';
        $info['objectClass'][3] = 'dkimmailrecipient';
        $info['DKIMSelector'] = $sel;

        syslog (LOG_INFO,  $username.' Info: LDAP: adding DKIM Identity for '.$subdom);
        return add_ldap ($ds, $dn, $info, $err);
}



function add_dkim_email_ldap($ds, $base, $dom, $email, $alias, $gn, $sn, $sel, $selclass, &$err) {
        /* Add signing path for a new email */
	// $sel = <selclass><sep><hashtag>

	$username = username();
        $edom = substr(strstr($email, '@'),1);
        $uid = strstr($email, '@',TRUE);
        if ( strpos($edom,$dom) === FALSE ) {
                $err = "LDAP: You are trying to add an email with <$edom> which is not a subdomain of <$dom>.";
                syslog(LOG_ERR, $username." Info: $err");
                return FALSE;
        }

        if (! dns_getMX ($edom, $err)) 
               return FALSE;

        /* Prepare the data to add */
        if ( $edom === $dom )
                $dn = "uid=$uid,ou=SigningTable,ou=$dom,ou=$selclass,$base";
        else
        {
                $dnbase = 'ou='.substr($edom, 0, strrpos($edom,'.'.$dom)).",ou=SigningTable,ou=$dom,ou=$selclass,$base";
                if (is_tree( $ds, $dnbase, 'DKIMSelector' ) )
                        $dn = "uid=$uid,$dnbase";
                else {
                        $err = "LDAP: You MUST define the default DKIM Identity of subdomain <$edom> before to add an email.";
                        syslog(LOG_ERR, $username." Info: $err");
                        return FALSE;
                }
        }

        /* Entry */
        $info['DKIMIdentity'] = $email;
        $info['mail'] = $email;
        $info['uid'] = $uid;
        $info['objectClass'][0] = 'top';
        $info['objectClass'][1] = 'person';
        $info['objectClass'][2] = 'organizationalPerson';
        $info['objectClass'][3] = 'inetorgperson';
        $info['objectClass'][4] = 'dkim';
        $info['objectClass'][5] = 'dkimmailrecipient';
        $info['DKIMSelector'] = $sel;
        $info['givenName'] = $gn;
        $info['sn'] = $sn;
        $info['cn'] = $gn.' '.$sn;

        syslog(LOG_INFO, $username." Info: LDAP: adding DKIM email identity <$email> to <$dom> key.");
        if (!is_null($alias)) {
                $adom = substr(strstr($alias, '@'),1);
		if (! dns_getMX ($adom, $err)) return FALSE;
                if ( strpos($adom,$edom) === FALSE ) {
                        $err = "LDAP: You try to add an email with <$adom> which is not a subdomain of <$edom>.";
                        syslog(LOG_ERR, $username." Info: $err");
                        return FALSE;
                }
                $info['mailAlternateAddress'] = $alias;
                syslog(LOG_WARNING, $username." Warn: LDAP: adding DKIM alias email identity <$alias> for <$email> to <$dom> key.".
                        ' This could cause warning at higher reputation level.');
        }

        if ( add_ldap ($ds, $dn, $info, $err) ) return TRUE;
        return FALSE;
}



function is_already($ds, $base_dn, $dom) {
/* Check if dom and parents is already present on DKIM LDAP setup as domain or SigningTable's subdomain */
	if (! ($occurrence = strstr($dom, '.')) )
		return FALSE;
	if ( ($sr = ldap_search($ds, $base_dn, "(&(objectclass=organizationalunit)(ou=$dom))",array('ou'),1)) === FALSE )
		return FALSE;
	$info = ldap_get_entries($ds, $sr);
	if ( $info["count"] ) return TRUE;

	return is_already($ds, $base_dn, $dom = substr($occurrence,1));
}



function subdomains($ds,$base_dn, $dom, $selclass) {
/* Return a list of signing subdomains of $dom */
        $dn = "ou=SigningTable,ou=$dom,ou=$selclass,$base_dn";
        if  ( $sr = ldap_list($ds, $dn, '(&(objectclass=dkim)(ou=*))', array('ou')) )
                return ldap_get_entries($ds, $sr);
        return FALSE;
}



function signemails($ds,$base_dn, $dom, $selclass) {
/* Return a list of signing VIP emails of $dom */
        $dn = "ou=SigningTable,ou=$dom,ou=$selclass,$base_dn";
        if  ( $sr = ldap_search($ds, $dn, '(&(objectclass=dkim)(uid=*)(mail=*))', array('DKIMIdentity')) )
                return ldap_get_entries($ds, $sr);
        return FALSE;
}



function currentLDAPSel ($ds, $dn, &$err) {
/* Return current selector as <selclass><sep><hashtag> */
	$username = username();
        if  ( $sr = ldap_read($ds, $dn, 'DKIMSelector=*', array('DKIMSelector')) ) {
                $info = ldap_get_entries($ds, $sr);
                if ( $info['count'] != 1 ) {
                        $err = 'LDAP: Error in number of DKIMSelector values. Returned: '.$info['count'].'. Expected: 1';
                        syslog(LOG_EMERG, $username.": Danger: $err.");
                        return FALSE;
                }
                return $info[0]['dkimselector'][0];
        }
        $err = 'LDAP: I can\'t find any DKIMSelector! Reason: '.ldap_error($ds);
        syslog(LOG_EMERG, $username.": Danger: $err.");
        return FALSE;
}



/* DNS Class */ 

function readRecord($dom, $type) {
/* Return  records for $dom or:
        FALSE if no record is found  or errors */

        $user = username();
        $value = array();
        $records = dns_get_record($dom,DNS_TXT);
        if ($records === FALSE) {
                syslog(LOG_ERR, "$user: DNS: error in query.");
                return FALSE;
        }
        $count = 0;
        if (isset($records[0]['entries']))
                foreach ( $records as $record ) {
                        $ok = FALSE;
                        switch ($type) {
                        /* I don't check validity of record name, only value... */
                                case 'DKIM':
                                        if ( substr( $record['entries'][0], 0, 8 ) === 'v=DKIM1;' )
                                                $ok = TRUE;
                                        break;
                                case 'SPF':
                                        if ( substr( $record['entries'][0], 0, 7 ) === 'v=spf1 ' )
                                                $ok = TRUE;
                                        break;
                                case 'DMARC':
                                        if ( substr( $record['entries'][0], 0, 8 ) === 'v=DMARC1' )
                                                $ok = TRUE;
                                        break;
                                default:
                                        syslog(LOG_ALERT, "$user: DNS: invalid record type specified.");
                                        return FALSE;
                        }
                        if ( $ok ) {
                                $count ++;
                                $value[] = $record['entries'][0];
                        }
                }
        else return FALSE;
        if ( $count == 0 ) return FALSE;
        else return $value;
}



function thisRecord($dom,$type,$sel,&$recordfound = FALSE) {
/* Read record specifically for DKIM */
// $sel = <selclass><sep><hashtag>

	$username = username();
	switch ( $type ) {
		case 'DKIM':
			if ( $recordfound = dns_get_record($sel.'._domainkey.'.$dom,DNS_TXT) )
				if ( substr( $recordfound[0]['txt'], 0, 7 ) === 'v=DKIM1' )
					return $recordfound[0]['txt'];
				else syslog(LOG_WARNING, $username.": Warn: DNS: <$dom> for selector <$sel> has an invalid DKIM record");
			else syslog(LOG_WARNING, $username.": Warn: DNS: <$dom> doesn't have a DKIM record for selector <$sel>.");
			return FALSE;
	}
}



function is_own($dom, $nameservers) {
	$ns = dns_get_record($dom,DNS_NS);
	foreach ( $ns as $name )
        	if ( in_array($name['target'],$nameservers) )
                	return TRUE;
	return FALSE;
}




function dns_pardom_get_record (&$dom,$type,$strictmode) {
/* Find first record on parent dom of at least second level */
/* Return the record and the associated subdomain */
/* Really not used for DKIM... */
// $selector = <selclass><sep><hashtag>

	if (! ($occurrence = strstr($dom, '.')) )
		return FALSE;

	switch ( $type ) {
		/* case 'DKIM':
			$recordname = $selector . "._domainkey.$dom";
			break;
		*/
		case 'DMARC':
			$recordname = "_dmarc.$dom";
			break;
		default:
			return FALSE;
	}
	
	if ( $record = readRecord($recordname, $type) )
		return $record;
	if ($strictmode) return FALSE;
	if ( $dom == orgDom($dom) ) return FALSE;
	else {
		$dom = substr($occurrence,1); 
		return dns_pardom_get_record ( $dom, $type, $strictmode );
	}
}



function dns_getMX ($dom, &$err) {
/* Return TRUE if $dom has not null MX record */
	$err = NULL;
	$return = getmxrr ( $dom, $mx );
	if ( $return ) {
		if ( in_array('.',$mx) ) {
			$err = "DNS: <$dom> has null MX record.";
			$return = FALSE;
		}
		else $err = "DNS: <$dom> has valid MX records.";
	}
	else $err = "DNS: <$dom> doesn't have any MX record!";
	syslog(LOG_INFO, username().": Info: $err");
	// $return = TRUE; // ***** -- >> Remember to remove this line! << -- *****
	return $return;
}


function remove_dkim_dns($drv_del,$ds,$delay_dn,$dom,$sel,&$err) {
/* Unlucky function title. Really is a *Delay delete* for the selector */
	$username=username();
        switch ( $drv_del ) {
                case 'mysql':
                        $db = parse_ini_file('db.conf', true);
                        if (! isset($db['port']) ) $db['port'] = ini_get("mysqli.default_port");
                        $mysql = mysqlconn($db['host'], $db['user'], $db['pass'], $db['name'], $db['port'], $err);
                        if ( $mysql ) 
                                if (! mysql_delayed_delete($mysql,$db['table'],$sel,$dom,$err) )
                                        return FALSE;
                        return TRUE;
                case 'ldap':
                        if (! ldap_delayed_delete($ds,$delay_dn,$sel,$dom,$err) ) {
				syslog(LOG_ERR, $username.": Error: I can't delay delete <$sel>");
                                return FALSE;
			}
                        return TRUE;
                default:
                        syslog(LOG_ALERT, $username.": Alert: Unknown driver <$drv_del>. Won't delete DKIM record of <$dom>.");
			return FALSE;
        }
}


function nsupdate($data, &$err) {
	// run DNS update
	if (version_compare(PHP_VERSION, '7.0.0') < 0) 
		$tmpfile = uniqid('nsupdate-') . '.txt';
	else
		$tmpfile = 'nsupdate-' . bin2hex(random_bytes(4)) . '.txt';
	$username = username();
	if (! file_exists('/usr/bin/nsupdate') ) {
                $err = 'DNS: nsupdate doesn\'t exist.';
                syslog(LOG_ALERT, $username.": Error: $err");
                return FALSE;
	}
	if ( file_exists($tmpfile) )
		if ( unlink ($tmpfile) )
			syslog(LOG_INFO, $username.': Warn: DNS: nsupdate tmp file already present. I deleted it.');
	if ( file_put_contents($tmpfile, $data) === FALSE ) {
		$err = 'DNS: Can\'t write tmp file for nsupdate.';
		syslog(LOG_ALERT, $username.": Error: $err");
		return FALSE;
	}
	exec("/usr/bin/nsupdate $tmpfile 2>&1", $ret, $status);
	if ($status !== 0)  {
		$err = "DNS: Update failed with code <$status>. File <$tmpfile> preserved for evidences.";
		if (! empty($ret) )
			$err .= ' Reason: <'.implode(' - ',$ret).'>.';
		syslog(LOG_ALERT, "$username: Error: $err");
		return FALSE;
	}
	else
		$err = 'DNS: Operation successfull.';
	if (! empty($ret) )
		$err .= ' Details: <'.implode(' - ',$ret).'>.';


	//if ( substr_compare($ret, 'update failed', 0, 13) == 0 ) {
	//	$err = "DNS: Changing DNS failed with status <$ret>.";
	//	syslog(LOG_ALERT, "$username: Error: $err");
	//	return FALSE;
	//}

	if ( unlink ($tmpfile) )
		syslog(LOG_INFO, $username.': Info: DNS: nsupdate tmp file successfully deleted after nsupdate call.');

	syslog(LOG_INFO,"$username: Info: $err");
	return TRUE;
}



function updatezone($servers, $action, $record, $TTL, &$errors, $zone=NULL) {
	$errors = NULL;
	if ( !( ($action == 'add') OR ($action == 'delete') ) ) {
		$errors = 'Update action must be "add" or "delete", not "'.$action.'".';
                return FALSE;
        }
	if (is_array($servers))
		$ret = TRUE;
	else {
		$errors = 'No nameservers given for nsupdate';
		return FALSE;
	}
	$username = username();

	if (! isset($record['value']) )
		$record['value'] = '';
	foreach ( $servers as $type => $server ) {
		$data = NULL;
		syslog(LOG_INFO, "$username: Info: DNS: Preparing to $action record {$record['type']} <{$record['dom']}> on $type server $server.");
		if ( !is_null($zone) )
			$data = "zone $zone\n";
		$data .= <<<EOF
			server $server
			prereq {$record['prereq']}
			update $action {$record['dom']} $TTL {$record['type']} {$record['value']}
			send
			quit
EOF;
		if ( !nsupdate($data, $err) )
			$ret = FALSE;
		$errors .= $err." Server: $server.\r\n";
	}
	return $ret;
}


/* Mysql class */
function mysqlconn($dbhost, $dbuser, $pwd, $db, $dbport,&$err) {
	$user = username();
	$err = FALSE;
	$mysqli = new mysqli($dbhost, $dbuser, $pwd, $db, $dbport);
        if ($mysqli->connect_error) {
		$err = "MySQL: Could not connect to MySQL server <$dbhost> on DB <$db> as user <$dbuser>. Reason: ".
			$mysqli->connect_error.' (' . $mysqli->connect_errno . ')';
		syslog (LOG_EMERG, $user.': Error: '.$err);
		return FALSE;
        }
	syslog (LOG_INFO, $user.': Info: MySQL: Successfully connected to MySQL server ' . $mysqli->host_info . " on DB <$db> as user <$dbuser>.");
	return $mysqli;
}



function mysqladd($mysqli,$value,$table,&$err) {
	$user = username();
	$query= sprintf("INSERT INTO `$table` ( `value` ) VALUES ( '%s' )" ,$value);
        if ($mysqli->query($query) === TRUE) {
	    $err = "MySQL: <$value> successfully added to table <$table>";
            syslog(LOG_INFO, $user.": Info: $err");
            return TRUE;
        }
        else {
		$err = "MySQL: Unable to add <$value> to table <$table>. Reason: ".$mysqli->error;
		syslog(LOG_ERR, "$user: Error: $err");
	}
        return FALSE;
}



function mysqldel($mysqli,$value,$table,&$err) {
        $user = username();
        $query= sprintf("DELETE FROM `$table` WHERE `value`='%s'" ,$value);
        if ($mysqli->query($query) === TRUE) {
            $err = "MySQL: <$value> successfully deleted from table <$table>";
            syslog(LOG_INFO, $user.": Info: $err");
            return TRUE;
        }
        else {
                $err = "MySQL: Unable to delete <$value> from table <$table>. Reason: ".$mysqli->error;
                syslog(LOG_ERR, "$user: Error: $err");
        }
        return FALSE;
}



function mysql_delayed_delete($mysql,$table,$sel,$dom,&$err) {
        /* Insert old key in the delayed delete db */
	// $sel = <selclass><sep><hashtag>

        $oldDKIMrecord = $sel.'._domainkey.'.$dom;
        if ( mysqladd($mysql,$oldDKIMrecord,$table,$err) )
                return TRUE;
        else 
                return FALSE;
        
}



function mysql_isDelayedRecord($db, $record) {
/* Return  TRUE if the DNS record is in delayed deleted state */
/* $record contains the name of the record, not the value */

        $user = username();
        $table = $db['table'];

       /* Looking for record's values */
        $query = sprintf("SELECT `value` FROM `$table` WHERE `value` = '%s'" ,$record);
        // connect
        if (! isset($db['port']) ) $db['port'] = ini_get("mysqli.default_port");
        $mysqli = mysqlconn($db['host'], $db['user'], $db['pass'], $db['name'], $db['port'], $err);
        if ( !$mysqli )
                return FALSE;
        if ($res = $mysqli->query($query)) {
                switch ($res->num_rows > 1 ? '2':$res->num_rows) {
			case 0:
                                $res->close();
                                $mysqli->close();
				syslog(LOG_INFO, "$user: Info: LDAP: The record <$record> is currently active.");
				return FALSE;
			case 1:
				syslog(LOG_INFO, "$user: Info: LDAP: The record <$record> is delayed deleted.");
                                $res->close();
                                $mysqli->close();
				return TRUE;
			case 2:
				syslog(LOG_ERR, "$user: Error: MySQL: It seems that <$record> is duplicated in DB.");
				$res->close();
				$mysqli->close();
				return FALSE;
			default:
				syslog(LOG_ERR, "$user: Error: MySQL: some error during query: ".$mysqli->error);
		}		
	}
        $res->close();
        $mysqli->close();
        return FALSE;
} 



function mysql_deleteOldRecord($db, $nsupdateconf, $mydate) {
/* Delete record based on his MySQL timestamp value  */
/* We assume the timezone is managed by MySQL Engine */
/* $mydate can have DST comment, anyway is ignored
   during query */

        $records = array();
	$user = username();
	$table = $db['table'];

	/* Looking for record's values */
	$query = sprintf("SELECT `value` FROM `$table` WHERE `date` < '%s'" ,$mydate);
        // connect
	if (! isset($db['port']) ) $db['port'] = ini_get("mysqli.default_port");
        $mysqli = mysqlconn($db['host'], $db['user'], $db['pass'], $db['name'], $db['port'], $err);
        if ( !$mysqli ) 
		return FALSE;
	if ($res = $mysqli->query($query)) 
		while ($row = $res->fetch_assoc())
			$records[] = $row['value'];
	else  {
		syslog(LOG_WARNING, "$user: Warn: MySQL: Unable to find delayed deleted records. Reason: ".$mysqli->error);
		return TRUE;
	}
	$res->free();
	$nr = count($records);
	syslog (LOG_INFO, "$user: Info: $nr records delayed deleted before $mydate found.");

        /* Real delete */
	$ret = TRUE;
	$retM= FALSE;
        for ($i=0; $i<$nr; $i++) {
                if ( $retD = updatezone($nsupdateconf['name'], 'delete',
		array('dom' => $records[$i], 'prereq' => "yxdomain {$records[$i]}", 'type' => 'TXT'), '', $err) )
                        if ( $retM = mysqldel($mysqli,$records[$i],$table,$err) )
                                syslog (LOG_INFO, $user.': Info: record <'. $records[$i].'> deleted at all successfully.');
                        else syslog(LOG_ERR, $user.': Error: <'. $records[$i].'> deleted only from DNS and not from MySQL!');
                else syslog(LOG_ERR, $user.': Error: Can\'t delete <'.$records[$i].'> Reason: '.$err);
		$ret = $ret && $retD && $retM;
	}
	/* Return operation status */
        return $ret;
}
        	
	


	
/* High level class */

function getSelclass ($selclasses,$sel) {
	array_multisort(array_map('strlen', $selclasses), $selclasses); //sort by lenght
	$selclasses = array_reverse($selclasses);
	foreach ( $selclasses as $selclass )
		if (preg_match("/^$selclass/", $sel) == 1)
			return $selclass;
	return FALSE;
}


function listdom($ds,$base_dn, $selclass) {
/* Return a list of all signing domains with valid setup. */
	$username = username();
	$dn = "ou=$selclass,$base_dn";
	$list = array();
	if  ( $sr = ldap_list($ds, $dn, "(&(objectclass=organizationalunit)(ou=*))",array('ou')) ) {
		$info = ldap_get_entries($ds, $sr);
		for ($i=0; $i<$info["count"]; $i++) 
			if ( $sr = ldap_read ($ds,'ou=KeyTable,ou='.
			 $info[$i]['ou'][0].','.$dn, '(&(objectclass=organizationalunit)(dkimdomain='.$info[$i]['ou'][0].'))',
			 array('dkimselector','dkimkey'),0,1) ) {
				$keytable = ldap_get_entries($ds, $sr);
				if ( isset($keytable[0]['dkimkey']) AND isset($keytable[0]['dkimselector']) )
					if ( thisRecord($info[$i]['ou'][0],'DKIM',$keytable[0]['dkimselector'][0]) )
						if (! dns_getMX ($info[$i]['ou'][0], $err) )
							syslog(LOG_WARNING, $username.': Warn: DNS: <'.$info[$i]['ou'][0].
                                                	'> for <'.$selclass.'> excluded: '.$err);
						else
							$list[] = $info[$i]['ou'][0];
					else syslog(LOG_WARNING, $username.': Warn: DNS: <'.$info[$i]['ou'][0].
						'> for <'.$selclass.'> excluded: this domain has valid LDAP Keytable, but can\'t resolve any pubkey.');		
				else syslog(LOG_WARNING, $username.': Warn: LDAP: <'.$info[$i]['ou'][0].
	                                '> for <'.$selclass.'> excluded: this domain has LDAP tree for KeyTable, but no valid KeyTable');
			}
			else syslog(LOG_WARNING, $username.': Warn: LDAP: <'.$info[$i]['ou'][0].
                                        '> for <'.$selclass.'> excluded: can\'t find KeyTable on its LDAP tree.');
	}
	else syslog(LOG_ERR, $username.': Err: LDAP: no domain found for <'.$selclass.'>!');
	return $list;
}




function printSelectList ($array,$name,$attr) {
	if (!(is_array($array) AND ($array["count"] > 0))) return FALSE;
	$size = ($array["count"] < 4) ? '"'.$array["count"].'"' : "4";
	if ($array["count"] <= 4)
		$ret = '<div class="noscroll">';
	else $ret='';
        $ret .= "<select name=\"{$name}[]\" multiple size=$size>";
        for ($i=0; $i < $array["count"]; $i++)
        	$ret .= '<option value="'.$array[$i]['dn'].'">'.$array[$i]["$attr"][0].'</option>';
	if ($array["count"] <= 4) 
		return $ret.'</select></div>';
	else return $ret.'</select>';
}


function is_delayed($record,$delay_drv,$ldapconn=NULL) {
/* Check if a record is currently delayed deleted */
	$user = username();
	switch ( $delay_drv ) {
	        case 'ldap':
	                if ( ldap_isDelayedRecord($ldapconn, $record, parse_ini_file('ldap.conf', TRUE)['delaydel']) ) return TRUE;
			return FALSE;
	        case 'mysql':
	                if ( mysql_isDelayedRecord(parse_ini_file('db.conf', TRUE), $record) ) return TRUE;
			return FALSE;
	        default:
	                syslog(LOG_ERR, $user.
			": Error: Unknown driver <$delay_drv>. I can't check if a record is currently delayed deleted. Unexpected behavior.");
	}
	return FALSE;
}

function isCurrent($dkim, $sel, $selclass, $dom) {
/* Return TRUE if $sel for $selclass is for the current time slot */
	$selCur = buildSel ($dkim, $selclass, $dom);
	if ( $selCur === $sel ) return TRUE;
	return FALSE;
}




function dkim_setup ($ldapconn, $ldap,$dkim,$dom,$selclass,$sel,$opt) {
// $sel = <selclass><sep><hashtag>

	function delete_dom_form($domain,$selclass,$sel,$subdomains,$emails) {
		print <<<FORM
	        <form style="float:right" method="POST" name="DKIMDel" action="dkimdel.php"
		 onSubmit="xmlhttpPost('dkimdel.php', 'DKIMDel', 'DKIMResult', '<img src=\'/include/pleasewait.gif\'>'); return false;">
	        <table>
FORM;
		printTableHeader('',array('DELETE','NO','YES'),TRUE,'<input type="submit" class="btn" width=100% value="DELETE!">');
	        print <<<FORM
		<tbody>
	        <tr>
	        <td>Delete <b>$domain</b> from <b>$selclass</b> at all</td>
                <td><input type="radio" name="deldom" value="FALSE" checked></td>
                <td><input type="radio" name="deldom" value="TRUE"></td>
		</tr><tr>
FORM;
		if ($isSub = printSelectList ($subdomains,'subdomdn','ou'))
			print '<td><label>Subdomains</label> '.$isSub.'</td>'.
				'<td><input type="radio" name="delsub" value="FALSE" checked></td>'.
				'<td><input type="radio" name="delsub" value="TRUE"></td></tr>';
		if ($isMail = printSelectList ($emails,'maildn','dkimidentity'))
			print '<tr><td><label>Emails</label> '.$isMail.'</td>'.
				'<td><input type="radio" name="delmail" value="FALSE" checked></td>'.
				'<td><input type="radio" name="delmail" value="TRUE"></td></tr>';
		print <<<FORMEND
	        <input type="hidden" name="domain" value="$domain">
		<input type="hidden" name="selclass" value="$selclass">
		<input type="hidden" name="sel" value="$sel">
        	</tbody>
        	</table>
        	</form>
FORMEND;
	}


        /* Add Web Form for DKIM Keys and Signing Path; return TRUE if setup is complete. */

	$ldapconf = $ldap['server'];

	$add_key = <<<END
        <tr>
        <td>Add DKIM pair of Key</td>
        <td><input type="radio" name="addkey" value="FALSE" checked></td>
        <td><input type="radio" name="addkey" value="TRUE"></td>
        </tr>
END;

	$replace_key = <<<END
        <tr>
        <td>Renew the existing pair of Key<br /></td>
        <td><input type="radio" name="modkey" value="FALSE" checked></td>
        <td><input type="radio" name="modkey" value="TRUE"></td>
        </tr>
END;


	switch ( $opt ) {
		case 'del':
			$add_key = NULL;
			delete_dom_form( $dom, $selclass, $sel, subdomains($ldapconn,$ldapconf['baseDN'], $dom, $selclass),
								signemails($ldapconn,$ldapconf['baseDN'], $dom, $selclass) );
			break;
		case 'add':
			print '<p><img src="checked.gif">You can proceed with the initial DKIM setup.</p>';
			break;
		case 'renew':
			$add_key = $replace_key;
			break;
		default:
			return FALSE;
	}
	ldap_close($ldapconn);

        $quotedom = preg_quote($dom);
	print <<<TABLE
	<form method="POST" name="DKIM" action="dkimset.php" onSubmit="xmlhttpPost('dkimset.php', 'DKIM', 'DKIMResult', '<img src=\'/include/pleasewait.gif\'>'); return false;">
	<table>
TABLE;
	printTableHeader('',array('Manage','NO','YES'),TRUE,'<input type="submit" class="btn" width=100% value="Engage!">');
	print <<<TABLE
	<tbody>
	$add_key
	<tr>
	<td>Add subdomain which needs a DKIM Identity<br /><input type="text" placeholder="something.$dom"
		pattern="\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+$quotedom$\b"
                title="You must insert a FQDN subdomain of <$dom>"
		size="50" name="subdom"></td>
	<td><input type="radio" name="addsubdom" value="FALSE" checked></td>
	<td><input type="radio" name="addsubdom" value="TRUE"></td>
	<input type="hidden" name="domain" value="$dom">
	<input type="hidden" name="selector" value="$sel">
	</tr>
        <tr>
        <td>Add VIP email which needs a DKIM Identity <b>** SPERIMENTAL **</b><br />
	<div style="text-align: right">Email: <input type="email" placeholder="user@[sub.]$dom"
				title="You must insert an email address of $dom."
				pattern="\b^[a-z0-9._%+-]+@(?:[a-z0-9.-]+\.|)$quotedom$\b"
				size="50" name="email"><br />
	Alias: <input type="email" placeholder="alias@[sub.]$dom" size="50" name="alias" disabled
				title="You must insert an email address of $dom. Remember that aliases could cause warning at higher reputation level."
				pattern="\b^[a-z0-9._%+-]+@(?:[a-z0-9.-]+\.|)$quotedom$\b"><br />
	Name: <input type="text" placeholder="Name" size="50" name="gn"><br />
	Surname: <input type="text" placeholder="Surname" size="50" name="sn"></div></td>
        <td><input type="radio" name="addemail" value="FALSE" checked></td>
        <td><input type="radio" name="addemail" value="TRUE"></td>
        </tr>	
	</tbody>
	</table>
	</form>
TABLE;
	return TRUE;
}



function create_dkim_keys($domain,$selector, $pathOpenDKIM, $opt_str) {
// $sel = <selclass><sep><hashtag> obviously
	$username = username();
	if ( file_exists(__DIR__.'/'.$selector.'.private') )
		if ( unlink (__DIR__.'/'.$selector.'.private') )
			syslog(LOG_INFO, $username.': Warn: PrivKeyFile already present. I deleted it.');
        if ( file_exists(__DIR__.'/'.$selector.'.txt') )
                if ( unlink (__DIR__.'/'.$selector.'.txt') )
                        syslog(LOG_INFO, $username.': Warn: PubKeyFile already present. I deleted it.');

	if (! file_exists($pathOpenDKIM) )
		syslog(LOG_ALERT, $username.": Error: opendkim-genkey doesn't exist.");
	$gencommand = $pathOpenDKIM.' --directory='.__DIR__." $opt_str --append-domain --domain=$domain --selector=$selector";
	if (system($gencommand,$status) !== FALSE) syslog(LOG_INFO, $username.": Info: system call for $pathOpenDKIM succeeds");
	else syslog(LOG_ERR, $username.": Error: unable to execute system call for opendkim-genkey");
	if ( $status === 0 ) syslog(LOG_INFO, $username.": Info: opendkim-genkey terminated with success state for <$domain> and selector <$selector>.");
	else syslog(LOG_ALERT, $username.": Error: opendkim-genkey can't generate the keys for <$domain> and selector <$selector>. Check options and syntax in [genkey] section of file dkim.conf.");
	
	if ( file_exists(__DIR__.'/'.$selector.'.private') AND file_exists(__DIR__.'/'.$selector.'.txt') )
		return array(__DIR__.'/'.$selector.'.private', __DIR__.'/'.$selector.'.txt');
	return array(FALSE,FALSE);
}



function renewkeys($ds,$dn,$delaydn,$dom,$sel,$selclass,$keyopt,$nsupdateconf,$drv_del,$path_genK,&$errors) {
        /* Setup a new pubkey on DNS and a new privkey on LDAP conf
	   Input:
		$ds: LDAP resource link identifier, returned by ldap_connect(). 
		$dn: base DN of LDAP keys container.
		$delaydn: DN of delayed-deleted records.
		$dom: domain of sign (SDID)
		$sel: selector in the form <selclass><sep><hashtag>
		$selclass: selector class
		$keyopt: a bunch of additional parameters for opendkim-genkey
		$nsupdateconf: set of configuration for nsupdate (ns.conf)
		$drv_del: delay driver
			add: special value meaning a first pair of key for this domain
			mysql: mySQL driver
			ldap: LDAP driver
			others values produce no deletion, as add, but syslog alert!
		$err: returning errors or a finally success comment.
	
	   Return:
		-1:	Key file generation problem
		-2:	Error modifying pubKey over DNS
                -3:     Error modifying privKey over LDAP
		-4:	Keys renewed successfully, but with errors accessing Delayed Delete DB
		-5:	No MX record, exiting without any modifications.
		 0:	Keys renewed successfully
	**********************************************************************/

	$username = username();
	$errors = NULL;
	$curSel = NULL;
	if (! dns_getMX ($dom, $errors)) return -5;

	if ( $drv_del != 'add' ) {
		$dnT = "cn=CosTemplate_DKIMSelector,ou=$dom,ou=$selclass,$dn";
	        $curSel = currentLDAPSel ($ds, $dnT, $err);
		$errors .= $err;
	        if ( !$curSel ) {
			$err = 'LDAP: I have to modify the existing selector, but I can\'t find it!';
			$errors .= $err;
                        syslog(LOG_ERR, $username." Info: $err");
                        return  -1;
		}
	        if ( $curSel === $sel ) {
	                $err = "LDAP: The current selector is already <$sel>. I can't change key of existing selector.";
			$err .= ' Maybe you are trying to renew a key in current time slot. Please, be patient and wait the end of current time slot.';
			$errors .= $err;
	                syslog(LOG_ERR, $username." Info: $err");
	                return  -1;
        	}
	}
	
        list ($privfile,$pubfile) = create_dkim_keys($dom,$sel,$path_genK, $keyopt);
        if (!$privfile OR !$pubfile) {
                $errors = 'Unable to generate key files.';
                syslog(LOG_ALERT, $username.": Alert: $errors.");
                return -1;
        }
        $zone = file_get_contents($pubfile);
	if ( preg_match ('/TXT\s+[\(](?P<sign>(.|\n)*?) \)\s+;\s+'.escapeshellcmd("----- DKIM key $sel for $dom").'/',$zone,$pub) == 1)
                $dnsR['value'] = str_replace("\n\t",'',$pub['sign']);
	else {
                $errors = 'The newly generated record has an unexpected format. Refused.';
                syslog(LOG_ALERT, $username.": Alert: $errors");
                return -1;
	}



	/* Add pubkey */
	$dnsR['dom'] = $sel . '._domainkey.'. $dom;
	$dnsR['prereq'] = "nxdomain {$dnsR['dom']}";
	$dnsR['type'] = 'TXT';	
        if ( !updatezone($nsupdateconf['name'],'add',$dnsR,$nsupdateconf['TTL'],$err) ) {
		$errors = $err;
		unlink($pubfile);
                unlink($privfile);
		return -2;
	}
	$errors .= "\r\n".$err;

	/* Mod or add privKey */
	if ( $drv_del == 'add' ) {
	        if ( !add_dkim_ldap($ds,$dn,$dom,$sel,$selclass,file_get_contents($privfile),$err) ) {
			$errors = $err;
        	        unlink($pubfile);
                	unlink($privfile);
                	return -3;
		}
	}
	else
	        if ( !mod_dkim_ldap($ds,$dn,$dom,$sel,$curSel,$selclass,file_get_contents($privfile),$err) ) {
			$errors = $err;
	                unlink($pubfile);
	                unlink($privfile);
	                return -3;
	        }
	$errors .= $err;

        /* Delay delete for the old selector */
	switch ( $drv_del ) {
		case 'mysql':
	        	$db = parse_ini_file('db.conf', true);
	        	if (! isset($db['port']) ) $db['port'] = ini_get("mysqli.default_port");
	        	$mysql = mysqlconn($db['host'], $db['user'], $db['pass'], $db['name'], $db['port'], $errorc);
	        	if ( $mysql ) {
	                	if (! mysql_delayed_delete($mysql,$db['table'],$curSel,$dom,$errord) ) 
					return addErrorReturn ($errors, $errord, $pubfile, $privfile);
	        	} else
	                	return addErrorReturn ($errors, $errorc, $pubfile, $privfile);
			break;
		case 'ldap':
			if (! ldap_delayed_delete($ds,$delaydn,$curSel,$dom,$errord) )
				return addErrorReturn ($errors, $errord, $pubfile, $privfile);
			break;
		case 'add':
			syslog(LOG_INFO, "$username: Info: This is the first added key for <$dom>. No delayed-del needed.");
			break;
		default:
			syslog(LOG_ALERT, $username.": Alert: Unknown driver <$drv_del>. Won't delete previous DKIM record of <$dom>.");
	}

        unlink($pubfile);
        unlink($privfile);
	return 0;
}



function printEditRecord ($type, $record) {
                print '<table>';
                printTableHeader('',array('Record','Value'),TRUE,'<input type="submit" class="btn" width="100%" value="Engage">');
                print <<<RECORD
                <tbody>
                <tr><td colspan="2">Change at your own risk the record typing it directly:</td></tr>
                <tr><td>$type</td><td><input type="text" name="record" size="95" value="$record"></td></tr>
RECORD;
}



function delete_record_form($domain,$type) {
/* Form to delete ALL $type DNS record, where
	$type = 'DMARC'
	$type = 'SPF'			*/

        print <<<FORM
                <form style="float: right" method="POST" name="{$type}Del" action="{$type}del.php"
                 onSubmit="xmlhttpPost('{$type}del.php', '{$type}Del', '{$type}result', '<img src=\'/include/pleasewait.gif\'>'); return false;">
                <table>
FORM;
	printTableHeader('',array('DELETE','NO','YES'),TRUE,'<input type="submit" class="btn" width=100% value="DELETE!">');
        print <<<FORM
                <tbody>
                <tr>
                <td>Delete <b>$domain</b> from <b>$type</b> at all</td>
                <td><input type="radio" name="deldom" value="FALSE" checked></td>
                <td><input type="radio" name="deldom" value="TRUE"></td>
                </tr><tr>
                <input type="hidden" name="domain" value="$domain">
                </tbody>
                </table>
                </form>
FORM;
}




/* SPF class */

function printSel($bool) {
	if ($bool) return 'selected';
	else return '';
}


function printSelectListSelected ($array,$name) {
/* Return select list for web based on array:
[]['value']	= option value
[]['selected']	= bool
[]['desc'] = web description for option
*/

	$lenght = count($array);
        if (!(is_array($array) AND ($lenght > 0))) return FALSE;
	$ret = "<select name=\"$name\">";
        for ($i=0; $i < $lenght; $i++)
                $ret .= '<option value="'.$array[$i]['value'].'" '.printSel($array[$i]['selected']).'>'.$array[$i]['desc'].'</option>';
        $ret .= '</select>';
	return $ret;
}


function mod_spf($dom, $record, $use_tmpl, &$err) {

	$err = NULL;
        print <<<FORM
        <form method="POST" name="SPF" action="SPFset.php" onSubmit="xmlhttpPost('SPFset.php', 'SPF', 'SPFresult', '<img src=\'/include/pleasewait.gif\'>'); return false;">
FORM;
        $mech = explode(' ',$record);
        if ($mech[0] != 'v=spf1') return FALSE;

	if ($use_tmpl) {
		$nmech = count($mech);
		$modifier = NULL;
		$qualifier = NULL;
		$tmplout= '';
		for ($i = 1; $i < $nmech; $i++) {
			require('spf_config.php');
			/* See at http://tools.ietf.org/html/rfc7208#section-4.6.2 */
			$qualifier = substr ( $mech[$i] , 0 , 1 );
			switch ($qualifier) {
				case '+':
				case '-':
				case '~':
				case '?':
					$modifier = substr ( $mech[$i] , 1);
					break;
				default:
					$qualifier = '+';
					$modifier = $mech[$i];
			}

        	        if ( ($key= array_search( $modifier, array_column($modifiers, 'value'))) !== FALSE )
               		 	$modifiers[$key]['selected'] = TRUE;
			else {
	                	$err = 'SPF: not expected modifier found: <' . $modifier . '>';
	        	        syslog(LOG_ERR, username().": Error: $err.");
				$err .= '. You can go on typing your record directly, at your own risk.';
	                	$use_tmpl = FALSE;
				break;
			}

	                if ( ($key= array_search( $qualifier, array_column($qualifiers, 'value'))) !== FALSE )
	                	$qualifiers[$key]['selected'] = TRUE;

			$tmplout .=	'<tr><td>'.printSelectListSelected ($qualifiers,'qualifiers[]').'</td>'.
					'<td>'.printSelectListSelected ($modifiers,'modifiers[]').'</td></tr>'."\n";
		}
	}
	if ($use_tmpl) {
                print '<table>';
                printTableHeader('',array('Qualifier','Modifier'),TRUE,'<input type="submit" class="btn" width="100%" value="Engage">');
                print '<tbody>';
		print $tmplout;
	}
	else 	/* Let specify entire record */
		printEditRecord('SPF',$record);

	print '</tbody></table><input type="hidden" name="dom" value="'.$dom.'"></form><div id=\'SPFresult\'></div>';
	if ( empty($err) )
		return TRUE;
	return FALSE;
}


function makeSPFrecord( $parts,&$err=NULL ) {
        $record = 'v=spf1';
	$n = count ($parts['qualifiers']);
	if ($n != count (array_unique($parts['modifiers'])))
		$err = 'There are repeated modifiers.';
	if ($n == 0)
		$err = 'There are no modifiers.';
	if (!is_null($err)) return FALSE;
	if ( count (array_unique($parts['qualifiers']))===1)
		return $record. ' '. (($parts['qualifiers'][0] != '+') ? $parts['qualifiers'][0] : '') . 'all';
        for ($i=0;$i<$n;$i++) 
                $record .= ' '. (($parts['qualifiers'][$i] != '+') ? $parts['qualifiers'][$i] : '') . $parts['modifiers'][$i];
        return $record;
}



/* DMARC Class */

function orgDom($dom) {
/* Compute Organizational Domain of $dom and return it
   with jeremykendall/php-domain-parser			*/

	require_once 'vendor/autoload.php';
	$pslManager = new Pdp\PublicSuffixListManager();
	$parser = new Pdp\Parser($pslManager->getList());
	$host = $parser->parseHost($dom);
	return $host->registerableDomain;
}


function recordToArray($dmarc_record) {
        /* Make array like
                $tagvet['p'] = 'reject'
                $tagvet['aspf'] = 'r'   */
	$tagvet=array();
        $tags = explode(';',$dmarc_record);
        if ($tags[0] != 'v=DMARC1') return FALSE;
        array_shift($tags);
        foreach ( $tags as $tag ) {
                list($t,$v) = explode('=',$tag,2);
                $tagvet[trim($t)] = $v;
        }

	$urinames = array('rua','ruf');
	foreach ( $urinames as $uriname )
		if ( !isset($tagvet["$uriname"]) )
			$tagvet["$uriname"] = NULL;
	return $tagvet;
}


function printDMARCinput($tag, $name) {
	switch ( $name ) {
		case 'pct':
			return sprintf('<input type="number" name="%s" value="%d" min="0" max="100" title="%s">',$name,$tag['value'],$tag['desc']);
		case 'ri':
			return sprintf('<input type="number" name="%s" value="%d" min="3600" title="%s">',$name,$tag['value'],$tag['desc']);
		default:
			return sprintf('<input type="text" name="%s" value="%s" maxlenght="255" size="30" title="%s">',$name,$tag['value'],$tag['desc']);
	}
}




function makeDMARCrecord($part, $def, &$err=NULL) {
	/* rebuild record from its parts */
	function unsetIfset (&$this,$def,$thistag) {
		if ( isset($this["$thistag"]) AND isset($def["$thistag"]) )
			if ( $this["$thistag"] == $def["$thistag"] )
				unset( $this["$thistag"] );
	}
	
	/* Normalize parts */
	$tags = array_keys($part);
	foreach ( $tags as $tag )
		unsetIfset($part, $def, $tag);
	unset($tag);
	if ( !isset($part['p']) ) {
		$err = 'Missing required tag <p>';
		return FALSE;
	}
	else {
		if ( isset($part['sp']) )
			if ( $part['sp'] == $part['p'] ) unset ($part['sp']);
	}

	/* Make record */
	$record = 'v=DMARC1';
	foreach ($part as $tag => $value)
		if ( !empty($value) )
			$record .= '; '."$tag=$value";
	if (is_null($err)) return $record;
	return FALSE;
}
	


function setURIzone($ns,$dom,$tag,$uri,&$warning,&$error) {
	/* Return the zone based on URI record types,
	   see at rfc7489#section-7.1               
	   Return FALSE on errors, mismatches...    
	   Return TRUE if no record is needed.		*/

	$username = username();
	$error = array();
	$warning = array();
	switch ($tag) {
		case 'rua':
		case 'ruf':
			break;
		default:
			$err = "Invalid URI tag: <$tag>";
			$error[] = $err;
			syslog(LOG_ERR,$username.": $err");
	}

	$email = 'postmaster@invalid';
	$re = "/\\bmailto\\:\\s*\\b(?<email>[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,})(?:$|\\!(?<size>\\d+\\w)$)/i";
	if ( preg_match($re, $uri, $matches) === 1 ) {
		if (isset( $matches['email'] ))
			$email = $matches['email'];
		if (isset( $matches['size'] ))
			$warning[] = "You specify a $tag size in <$email>. This could reduce interoperability.";
	}
	else {
		$err = "Invalid <$tag> mail sintax.";
		$error[] = $err;
		syslog(LOG_ERR,$username.": $err");
	}

	list(,$edom) = explode('@',$email);
	if (! dns_getMX ($edom, $err))
		$error[] = $err;
	if ( orgDom($edom) != orgDom($dom) ) {
		$warn = "The Organizational domain of $tag domain <$edom> is not equal to the Organizational domain of <$dom>.".
			" A DMARC REPORT record in <$edom> is needed, as specified in RFC7489 section 7.";
		syslog(LOG_INFO,$username.": Info: DMARC REPORT: $warn");
		$warning[] = $warn;
		if ( is_own($edom, $ns) ) 
			return $dom.'._report._dmarc.'.$edom;
		else {
			$err = "You specify a $tag domain <$edom> which is not yours. I can't set the DMARC REPORT record.";
			syslog(LOG_ERR,$username.": Error: DMARC REPORT: $err");
			$error[] = $err;
		}
	}
	else return TRUE;
	return FALSE;
}	



function urirecords ($nameservers, $uris, $domain, $web=TRUE) {
/* From array of uri in form
   array (
	['rua'] => 'mailto: <value>[, ...]'
	['ruf'] => 'mailto: <value>[, ...]'
   )
   build a record of DMARC report uri names, such as
	<dom1>._report._dmarc.<dom>			 
   $web is a bool to print some info on HTML		*/

	$urirecs = array();
	foreach ( $uris as $tag => $urivet ) {
        	foreach ( $urivet as $uri ) {
                	$urirecord = setURIzone($nameservers,$domain,$tag,$uri,$warns,$errors);
                	if ( $urirecord === FALSE ) {
                        	if ( $web ) {
					print '<p><img src="unchecked.gif"> Error in <b>'.strtoupper($tag).'</b>: </p><pre>';
                        		foreach ( $errors as $err ) print htmlentities($err)."\n";
                        		print ('</pre><p>If you are in trouble, please report this error to a sysadmin.</p>');
				}
				return FALSE;
                	}
                if (count($warns) AND $web) {
			print '<p><img src="warning.gif"> There are some warnings on <b>'.$uri.'</b> for <b>'.strtoupper($tag).'</b>:</p><pre>';
                	foreach ( $warns as $warn ) print htmlentities($warn)."\n";
                	print '</pre>';
		}
                if (!is_bool($urirecord))
                        if(!in_array($urirecord, $urirecs))
                                $urirecs[] = $urirecord;
        	}
	}
	return $urirecs;
}


	
function mod_dmarc($dom, $record, $use_tmpl, &$err) {

	$err = NULL;
        print <<<FORM
        <form method="POST" name="DMARC" action="DMARCset.php" onSubmit="xmlhttpPost('DMARCset.php', 'DMARC', 'DMARCresult', '<img src=\'/include/pleasewait.gif\'>'); return false;">
FORM;

        if ($use_tmpl) {
                print '<table>';
                printTableHeader('',array('Tag','Value'),TRUE,'<input type="submit" class="btn" width="100%" value="Engage">');
                print '<tbody>';

		$thistags = recordToArray($record);
		if ( $thistags === FALSE ) $err .= 'Error in DMARC record syntax';
		$thistagnames = array_keys($thistags);
		$tags = array();
		require_once('dmarc_config.php');
		$tagnames = array_keys($tags);
		foreach ( $tagnames as $tag ) {
			$match = array_search( $tag, $thistagnames );
			if ( isset($tags["$tag"]['values']) and is_array($tags["$tag"]['values']) ) {	/* It's a set of option */
				if ($match !== FALSE) {
					if ( ($key= array_search( $thistags["$tag"], array_column($tags["$tag"]['values'], 'value'))) !== FALSE )
                                		$tags["$tag"]['values'][$key]['selected'] = TRUE;
					else $err .= "\r\n".'Current value of <'.$tags["$tag"]['desc'].'> ("'.$thistags["$tag"].'") seems to be wrong or not allowed. I can\'t let you keep this value.'."\n";
					if ( $tag == 'p' ) $keyp = $key;
				}
			} else
				if (isset($tags["$tag"]['value']))	/* It's a value */
					if ( ( isset($thistags["$tag"]) OR @is_null($thistags["$tag"]) ) AND ($match !== FALSE) )
						$tags["$tag"]['value'] = $thistags["$tag"];
		}

		/* Correct the sp value to p value, if it's not explicitly set */
		if ( isset($keyp) && !in_array('sp', $thistagnames) )
			$tags['sp']['values'][$keyp]['selected'] = TRUE;

		/* Print the form table */
		foreach ( $tagnames as $tag ) {
                        print '<tr><td>'.$tags["$tag"]['desc'].'</td>';
			if ( isset($tags["$tag"]['values']) and is_array($tags["$tag"]['values']) )    /* It's a set of option */
				print '<td>'.printSelectListSelected ($tags["$tag"]['values'],$tag).'</td>';
			else
				if ( isset($tags["$tag"]['value']) OR @is_null($tags["$tag"]['value']) )    /* It's a value */
					print '<td>'.printDMARCinput($tags["$tag"], $tag).'</td>';
		}

	} /* END of use_tmpl */	
        else	/* Let specify entire record */
		printEditRecord('DMARC',$record);

        print '</tbody></table><input type="hidden" name="dom" value="'.$dom.'"></form><div id=\'DMARCresult\'></div>';
	if (is_null($err)) return TRUE;
	return FALSE;
}


function updateRecord ( $dom, &$prev, $new, $type, $ns, &$err, $web = TRUE ) {
/* Function to update DMARC and SPF record
   $dom = domain fqdn
   &$prevRecord = return the value of record replaced.
   $new = new record value. If it is NULL I only delete current value.
   $type = 'DMARC', or 'SPF';
   $ns = DNS nsupdate configuration array
   $err = errors returned
   $web = a bool to print some additional info on HTML
   return TRUE or FALSE on errors					*/

	/* Some var by type */
	switch ( $type ) {
		case 'SPF':
		case 'DMARC':
			break;
		default:
			return FALSE;
	}

	$username = username();
	$dnsR = array();

	/* Consistency checks... */
	$err = NULL;
	$prev= NULL;
	$prevRecord = readRecord($dom, $type);
	if ( ( $prevRecord !== FALSE ) && ( $prevRecord[0] === $new ) )
        	$err = "The new $type record for <$dom> is equal to the old one.";
	if ( is_array($prevRecord) and (count($prevRecord) > 1) )
        	if ( is_null($err) )
                	$err = "There are too many $type record for <$dom>!! What have you done?! Oh damn...";
        else    	$err .= "\r\n".'And there are too many '.$type.' record for <'.$dom.'>!! What have you done?! Oh damn...';

	if (! is_null( $err ) ) {
        	syslog(LOG_ERR,"$username: Error: $type: $err");
        	if ( $web ) print'<p><img src="unchecked.gif">'. htmlentities($err) .'</p>';
		if ( !is_null($new) )
			return FALSE;
	}

        /* Update record */
	$prev = $prevRecord[0];
	if  ( $prevRecord === FALSE ) {
        	if ( $web ) printf ( '<p><img src="checked.gif"> There was no %s records for %s</p>', $type, htmlentities("<$dom>") );
		syslog ( LOG_INFO, "There was no $type record for <$dom>" );
	}
	else {
		/* Del old value */
        	$dnsR['dom'] = $dom;
                $dnsR['prereq'] = "yxdomain {$dnsR['dom']}";
                $dnsR['type'] = 'TXT';
        	if ( $type == 'SPF' ) { /* Delete only found values */
			foreach ( $prevRecord as $pr ) {
				$dnsR['value'] = '"'.$pr.'"';
		        	if ( updatezone($ns['name'],'delete',$dnsR,$ns['TTL'],$errors) ) {
		                	if ( $web )
						printf ( '<p><img src="checked.gif"> %s %s record with value %s deleted.</p><pre>%s</pre>',$type,
						htmlentities("<$dom>"), htmlentities("<$pr>"), htmlentities($errors) );
				}
		       	 	else {
		                	if ( $web )
						printf ( '<p><img src="unchecked.gif"> %s %s record delete errors.</p><pre>%s</pre>', $type,
						htmlentities("<$dom>"),htmlentities($errors) );
					$return = FALSE;
				}
				$err .= $errors."\r\n";
			}
		}
		else { /* Delete all record values, all in a row */
			if ( updatezone($ns['name'],'delete',$dnsR,$ns['TTL'],$err) ) {
				if ( $web )
        				printf ( '<p><img src="checked.gif"> %s %s record deleted.</p><pre>%s</pre>',$type,
        				htmlentities("<$dom>"), htmlentities($err) );
			}
			else {
				if ( $web )
					printf ( '<p><img src="unchecked.gif"> %s %s record delete errors.</p><pre>%s</pre>', $type,
                                                htmlentities("<$dom>"),htmlentities($err) );
				$return = FALSE;
			}
		}
		unset($dnsR);
	}

	/* Add the new value */
	if ( is_null($new) ) return TRUE;
	$dnsR['dom'] = $dom;
	$dnsR['value'] = '"'.$new.'"';
	if ( $type == 'SPF' )
		$dnsR['prereq'] = "yxdomain {$dnsR['dom']}";
	else
		$dnsR['prereq'] = "nxdomain {$dnsR['dom']}";
	$dnsR['type'] = 'TXT';

	if ( updatezone($ns['name'],'add',$dnsR,$ns['TTL'],$errors) ) {
	        if ( $web )
			printf ( '<p><img src="checked.gif"> %s %s record updated with value %s.</p><pre>%s</pre>', $type,
			htmlentities("<$dom>"), htmlentities("<$new>"), htmlentities($errors) );
	}
	else {
	        if ( $web )
			printf ( '<p><img src="unchecked.gif"> %s %s record update errors.</p><pre>%s</pre>', $type,
			htmlentities("<$dom>"),htmlentities($errors) );
		$return = FALSE;
	}
	$err .= $errors;
	unset($dnsR);

	/* Ensure return value */
	if (! isset($return) ) return TRUE;
	else return $return;
}



function version() {
	return '1.0';
}
?>
