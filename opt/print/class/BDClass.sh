#!/bin/bash
source /opt/print/config

## querySql
querySql="mysql --host=$HOST --password=$PASSWORD --user=$USER --database=$DATABASE";

####
## Usuários
####
function getIdUserSuap(){
	user_id=$(echo "SELECT id FROM users WHERE suap='$1'" | $querySql);
	user_id=$( echo $user_id | cut -d " " -f 2);
	echo $user_id;
}

function setUser(){
	user_id=$( getIdUserSuap $1 );	
	if [[ -z $user_id ]]; then
		echo "INSERT INTO users (id, suap, status) VALUE (null, '$1', 1);" | $querySql;
		user_id=$( getIdUserSuap $1 );
	fi
	echo $user_id;
}

####
## Impressoras
####
function getIdPrintName(){
	printer_id=$(echo "select id FROM printers where name='$1'" | $querySql);
	printer_id=$( echo $printer_id | cut -d " " -f 2);
	echo $printer_id;
}

function setPrint(){
	printer_id=$( getIdPrintName $1 );
	if [[ -z $printer_id ]]; then
		echo "INSERT INTO printers (id, name) VALUE (null, '$1');" | $querySql;
		printer_id=$( getIdPrintName $1 );
		# echo "ID: "$printer_id;
	fi
	echo $printer_id;
}

####
## INSERT jobs
####

function setJob(){
	echo "INSERT INTO jobs (id, user_id, printer_id, date, pages, copies, host, file) VALUE ($1, $2, $3, '$4', $5, $6, '$7', '$8');" | $querySql &>/dev/null;
	if [[ $? != 0 ]]; then
		echo "UPDATE jobs $1";
		echo "UPDATE jobs SET id=$1, user_id=$2, printer_id=$3, date='$4', pages=$5, copies=$6, host='$7', file='$8' WHERE id=$1;" | $querySql;
	fi
}