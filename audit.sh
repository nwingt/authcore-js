yarn audit
if [ $? -gt 4 ]
then
  exit 1
fi
exit 0