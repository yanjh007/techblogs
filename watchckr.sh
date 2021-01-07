#!/bin/bash                                                                        
                                                                                  
while true; do                                                                    
    ret1=`ps -aux | grep "store=data8 " | wc -l`                                  
    ret2=`ps -aux | grep "store=data8a " | wc -l`                                 
                                                                                  
    wall "The Node8/8A status is $ret1, $ret2"                                             
                                                                                  
    if [ $ret1 = 1 ] || [ $ret2 = 1 ]; then                                       
        /usr/sbin/ntpdate time.pool.aliyun.com                                    
    fi                                                                            
                                                                                  
    if [ $ret1 = 1 ]; then                                                        
       wall "Restart Node 8 ...."                                                 
       runuser -l cockroach  -c "/opt/cockroach/start8.sh"                        
    fi                                                                            
                                                                                  
    if [ $ret2 = 1 ]; then                                                        
       wall "Restart Node 8A ...."                                                
       runuser -l cockroach  -c "/opt/cockroach/start8a.sh"                       
    fi                                                                            
                                                                                  
    sleep 90                                                                      
done                                                                              
