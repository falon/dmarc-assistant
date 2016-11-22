<?php
$default = parse_ini_file('dmarc.conf', true);

	/* template (see at RFC7489) */
        $tags = array(
                'adkim'	=>	array(	'values' => array(
							array(	'value' => 'r',
								'desc' => 'Relaxed',
								'selected' => FALSE ),
                                                        array(  'value' => 's',
                                                                'desc' => 'Strict',
                                                                'selected' => FALSE ),
						),
					'desc'	=> 'DKIM Align',
				),
                'aspf' =>      array(  'values' => array(
                                                        array(  'value' => 'r',
                                                                'desc' => 'Relaxed',
                                                                'selected' => FALSE ),
                                                        array(  'value' => 's',
                                                                'desc' => 'Strict',
                                                                'selected' => FALSE ),
                                                ),
                                        'desc'  => 'SPF Align',
                                ),
                'fo' =>      array(  'values' => array(
                                                        array(  'value' => '0',
                                                                'desc' => 'All fail to align',
                                                                'selected' => FALSE ),
                                                        array(  'value' => '1',
                                                                'desc' => 'Any fails to align',
                                                                'selected' => FALSE ),
							array(  'value' => 'd',
                                                                'desc' => 'DKIM fail',
                                                                'selected' => FALSE ),
							array(  'value' => 's',
                                                                'desc' => 'SPF fail',
                                                                'selected' => FALSE ),
                                                ),
                                        'desc' => 'Failure reporting',
                                ),
                'p'  =>      array(  'values' => array(
                                                        array(  'value' => 'none',
                                                                'desc' => 'None',
                                                                'selected' => FALSE ),
                                                        array(  'value' => 'quarantine',
                                                                'desc' => 'Quarantine mail',
                                                                'selected' => FALSE ),
                                                        array(  'value' => 'reject',
                                                                'desc' => 'Reject mail',
                                                                'selected' => FALSE ),
						),
                                        'desc'  => 'Requested Policy',
                                ),
                'sp'  =>      array(  'values'=> array(
                                                        array(  'value' => 'none',
                                                                'desc' => 'None',
                                                                'selected' => FALSE ),
                                                        array(  'value' => 'quarantine',
                                                                'desc' => 'Quarantine mail',
                                                                'selected' => FALSE ),
                                                        array(  'value' => 'reject',
                                                                'desc' => 'Reject mail',
                                                                'selected' => FALSE )
						),
                                        'desc'  => 'Requested Subdomains Policy',
                                ),
                'pct'  =>      array(  'value'=> $default['pct'],
                                        'desc'  => 'Percentage Policy',
                                ),
                'rf'  =>      array(  'values'=> array(
							array(	'value' => 'afrf',
								'desc' => 'AFRF',
								'selected' => FALSE )
						),
                                        'desc'  => 'Failure Report format',
				),
                'ri'  =>      array(  'value'=> $default['ri'],
                                        'desc'  => 'Interval',
                                ),
                'rua'  =>      array(  'value'=> isset($default['rua']) ?: TRUE,
                                        'desc'  => 'addresses for Aggregate Report',
				),
                'ruf'  =>      array(  'value'=> isset($default['ruf']) ?: TRUE,
                                        'desc'  => 'addresses for Failure Report',
                                ),
	);
?>
