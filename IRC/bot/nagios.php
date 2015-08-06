<?php
/*
###############
## HackThisSite Nagios IRC Bot
##
## By Kage
## http://www.hackthissite.org
##
## Uses the ProtoIRC framework
## This bot connects to an IRC server and checks that particular things are
## online, namely responses to /WHOIS and /MAP.  Used to check that services
## like NickServ and ChanServ are online, and that leaf nodes are connected.
## Also reports the current online users per leaf and overall.
##
##  Copyright (c) 2013 Kage, HackThisSite.org
##
##  Redistribution and use in source and binary forms, with or without
##  modification, are permitted provided that the following conditions
##  are met:
##  1. Redistributions of source code must retain the above copyright
##     notice, this list of conditions and the following disclaimer.
##  2. Redistributions in binary form must reproduce the above copyright
##     notice, this list of conditions and the following disclaimer in the
##     documentation and/or other materials provided with the distribution.
##
##  THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
##  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
##  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
##  ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
##  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
##  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
##  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
##  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
##  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
##  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
##  SUCH DAMAGE.
##
*/

require(dirname(__FILE__).'/config.php');
require_once(dirname(__FILE__).'/protoirc.php');

// Signal catchers
declare(ticks = 1);
pcntl_signal(SIGTERM, "signal");
pcntl_signal(SIGINT, "signal");
pcntl_signal(SIGHUP, "signal");
function signal($signal) {
  global $irc, $config;
  if ($config->DAEMON) {
    toLog('Received signal ('.$signal."), shutting down...\n");
  } else {
    $irc->stdout("{$irc->ansi->_black}[{$irc->ansi->_red}ALERT{$irc->ansi->_black}] Received signal: {$signal}\n");
  }
  $irc->send('QUIT Killed...');
  $irc->close();
  exit;
}

function toLog($line) {
  global $config;
  return file_put_contents($config->LOG, '['.date('m/d/y H:i:s').'] '.$line."\n", FILE_APPEND);
}

if ($config->DAEMON) toLog('Daemon started.  Establishing event handlers ...');

$globals = (object)array('ONLINE' => time(), 'DATA' => array(), 'MAP' => array());

function arrLower($val, $key, $arr) {
  global $config;
  $config->{$arr}[$key] = strtolower($val);
}
array_walk($config->BOTS, 'arrLower', 'BOTS');
array_walk($config->NODES, 'arrLower', 'NODES');

// Establish connection settings and actions
$irc = new ProtoIRC(($config->SSL?'ssl':'irc').'://'.$config->NICK.':'.$config->PASS.'@'.$config->SERVER.':'.$config->PORT.'/'.str_replace('#','',$config->CHANNELS), function ($irc) {});



// JSON timer
$irc->timer(1, function ($irc) use (&$config, &$globals) {
  if ((time() - $globals->ONLINE) <= 5) return; // Delay initial run
  if (isset($globals->DATA['bots']) && isset($globals->MAP['DONE'])) {
    if (count(array_diff($config->BOTS, array_keys($globals->DATA['bots']))) === 0 && $globals->MAP['DONE']) {
      $globals->DATA['time'] = time();
      file_put_contents($config->FILE, json_encode($globals->DATA));
      $globals->MAP['DONE'] = false;
      $output = 'DEBUG: JSON data file written';
      if ($config->DAEMON) {
        toLog($output);
      } else {
        $irc->stdout("<< {$output}\n", '_black');
      }
    }
  }
});

// Check timer
$irc->timer($config->DELAY, function ($irc) use (&$config, &$globals) {
  if ((time() - $globals->ONLINE) <= 5) return; // Delay initial run
  $globals->MAP = array();
  $globals->DATA['bots'] = array();
  $irc->map(' ');
  foreach ($config->BOTS as $bot) $irc->whois($bot);
});

// Config rehash
$irc->in('/^:(.*) PRIVMSG (.*) :!rehash/i', function ($irc, $nick, $channel) use (&$config) {
  if (strtolower($nick) == strtolower($config->ADMIN)) {
    require(dirname(__FILE__).'/config.php');
    preg_match('/(.*)!.*/', $nick, $nickShort);
    $irc->send((strtolower($channel) == strtolower($irc->nick) ? $nickShort[1] : $channel), 'Configuration rehashed');
  }
});



// RAW 006: Map tree node
$irc->in('/^:.* 006 .* :(.*)/', function ($irc, $mapNode) use (&$globals) {
  $nodeClean = trim(preg_replace('/[^a-zA-Z0-9\.-]/', ' ', $mapNode));
  $nodeClean = preg_replace('/^-(.*)$/', '\\1', $nodeClean);
  array_push($globals->MAP, $nodeClean);
});

// RAW 007: Map tree end
$irc->in('/^:.* 007 .*/', function ($irc) use (&$config, &$globals) {
  $nodes = array();
  $onlineUsers = 0;
  foreach ($globals->MAP as $leaf) {
    $leaf = trim($leaf);
    $leafInfo = preg_split('/[ ]+/', $leaf);
    $nodes[strtolower($leafInfo[0])] = $leafInfo[1];
    if (strtolower($leafInfo[0]) != 'irc-services.hackthissite.org') $onlineUsers += $leafInfo[1];
  }
  foreach ($config->NODES as $node) {
    $globals->DATA['nodes'][$node] = (isset($nodes[$node]) ? $nodes[$node] : -1);
  }
  $globals->DATA['online'] = $onlineUsers;
  $globals->MAP['DONE'] = true;
});

// RAW 311: Whois return online
$irc->in('/^:.* 311 .* (.*) .* .* .* :.*/', function ($irc, $user) use (&$config, &$globals) {
  $user = strtolower($user);
  if (!in_array($user, $config->BOTS)) return;
  $globals->DATA['bots'][$user] = true;
});

// RAW 376: MOTD end
$irc->in('/^:.* 376 .*/', function ($irc) use (&$config, &$globals) {
  $irc->oper($config->OPER);
});

// RAW 401: Whois return offline
$irc->in('/^:.* 401 .* (.*) :.*/', function ($irc, $user) use (&$config, &$globals) {
  $user = strtolower($user);
  if (!in_array($user, $config->BOTS)) return;
  $globals->DATA['bots'][$user] = false;
});

// MODE: Usermode
$irc->in('/^:.* mode .* :(.*)/i', function ($irc, $mode) use (&$config) {
  if (strpos($mode, 'r')) foreach (explode(',', $config->CHANNELS) as $channel) $irc->join($channel);
});

// KICK: Channel rejoin
$irc->in('/^:.* kick (.*) (.*) :.*/i', function ($irc, $channel, $user) use (&$config) {
  if (strtolower($user) == strtolower($config->NICK)) $irc->join($channel);
});


if (!$config->DAEMON) {
  // Send raw IRC data by typing "/quote SOME DATA TO SEND"
  $irc->stdin('/^\/(quote|raw) (.*)/', function ($irc, $command, $data) {
    $irc->send($data);
  });

  // Send to channel by typing "#channel, message"
  $irc->stdin('/^([#\-[:alnum:]]*), (.*)/', function ($irc, $channel, $msg) {
    $irc->send($channel, $msg);
  });

  // Catch-all: Send to default channel
  $irc->stdin('/(.*)/', function ($irc, $msg) {
    $irc->send($irc->last, $msg);
  });
}

// Catch-all: Print raw line to terminal for debugging/hacking
$irc->in('/(.*)/', function ($irc, $line) use (&$config) {
  if ($config->DAEMON) {
    toLog($line);
  } else {
    $irc->stdout("<< {$line}\n", '_black');
  }
});

if ($config->DAEMON) toLog("Connecting ...\n");

// Everything bound.  Proceed.
$irc->go($config->DAEMON);
