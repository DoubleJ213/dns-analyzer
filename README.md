Requirements:

~~~

export PCAPV=1.9.1
# LIBPCAP_PATH=/data/project/src/dns-analyzer/main
LIBPCAP_PATH=`pwd`
wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz && \
    tar xvf libpcap-$PCAPV.tar.gz && \
    cd libpcap-$PCAPV && \
    ./configure --with-pcap=linux && \
    make

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build --ldflags "-L ./libpcap-$PCAPV -linkmode external -extldflags \"-static\"" -a -o main .

export LD_LIBRARY_PATH="-L<$LIBPCAP_PATH/libpcap-1.9.1>/libpcap-$PCAPV"
export CGO_LDFLAGS="-L<$LIBPCAP_PATH//libpcap-1.9.1>/libpcap-$PCAPV"
export CGO_CPPFLAGS="-I<$LIBPCAP_PATH/libpcap-1.9.1>/libpcap-$PCAPV"

~~~

Build:

~~~
cd main
go build
~~~

Get started:

~~~
[root@coredns-d-010058012152 tdops]# ./main -i eth0 
build vm info from file /opt/dns-an/data.txt
build vm info from file /opt/dns-an/data.txt done
config file /opt/dns-an/config/hz-te-vpc.conf
There are 49 pods in the cluster
load pods info from /opt/dns-an/config/hz-te-vpc.conf  into memory.
load done
Live Capture Started...
Capture: app wjj-test-d68fb58fc-q8468 ip 10.59.163.219 query kubernetes.default.svc.cluster.hz-test answered by 10.59.192.1
Capture: app wjj-test-d68fb58fc-q8468 ip 10.59.163.219 query sentinel-gitlab-service.default.svc.cluster.local answered by 10.59.1.194
~~~

Others:

~~~
offlineCapture comming soon
~~~