
echo "SELECT ID FROM TESTTBL WHERE RNDSTR='AAAA' or RNDSTR2='zzzz';" | ./sqlite-$1-$2/sqlite3 ./nuovo.db &>dev/null;
exit $?;
