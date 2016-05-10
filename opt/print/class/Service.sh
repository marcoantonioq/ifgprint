#!/bin/bash
source /opt/print/config

function status(){
	ps aux | 
	egrep $1 |
	grep -v grep;
}

function stop(){
	process=$( 
		status $1 | 
		awk '{print "kill " $2}'
	);
	echo -e "$process";
	$process &>/dev/null
}