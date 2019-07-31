yarn audit
if [ $? -eq 4 ]
then
  exit 1
fi
exit 0