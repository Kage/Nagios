<?php
$config = (object)array(

// True writes to log, false outputs to terminal
'DAEMON' => true,

// Administrator
'ADMIN' => 'Nick!Ident@Vhost',

// Daemon log file
'LOG' => 'bot.log',

// IRC host
'SERVER' => '10.10.10.10',

// IRC port
'PORT' => 6667,

// Is PORT SSL or plain?
// SSL port is unneeded when run locally
'SSL' => false,

// Nick to use
'NICK' => 'Nagios',

// NickServ password
'PASS' => 'NickServPassword',

// Password to use when using /oper command
'OPER' => 'OperPassword',

// File where data is dumped, for Nagios check script
'FILE' => 'data.json',

// Channels to join (after auth) and place output
'CHANNELS' => '#admin',

// Polling delay (in seconds)
'DELAY' => 60,

// Bots
'BOTS' => array('ChanServ','NickServ','IdleRPG'),

// Map nodes
'NODES' => array('services.irc-network.org','leaf-1.irc-network.org','leaf-2.irc-network.org'),

);
