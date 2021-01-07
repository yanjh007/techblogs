!/bin/bash

## start use nohup /opt/watchckr.sh > /opt/watch.log 2>&1 & 

while true; do
    ret1=`ps -aux | grep "store=data8 " | wc -l`
    ret2=`ps -aux | grep "store=data8a " | wc -l`

    echo "The Nodes status is $ret1, $ret2  "`date`

    if [ $ret1 = 1 ] || [ $ret2 = 1 ]; then
        /usr/sbin/ntpdate time.pool.aliyun.com
    fi

    if [ $ret1 = 1 ]; then
       echo "Restart Node 8 ...."`date`
       runuser -l cockroach  -c "/opt/cockroach/start8.sh"
    fi

    if [ $ret2 = 1 ]; then
       echo "Restart Node 8A ...."`date`
       runuser -l cockroach  -c "/opt/cockroach/start8a.sh"
    fi

    sleep 90
done


                                                                     
