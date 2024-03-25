# install g++ / libpcap-dev / google test 

<body> deps.sh has function to install g++, libpcap-dev, libgtest-dev library by apt. </body>

###

<body> So, execute shell script if you need them. </body>

###

````
$ ./deps.sh
````


# How to make 'makefile'

````
$ qmake send-arp-test.pro
$ make
````


# Directory tree after build
````
├── deps.sh
├── include
│   ├── arphdr.h
│   ├── ethhdr.h
│   ├── getPacket.h
│   ├── ip.h
│   └── mac.h
├── Makefile
├── out
│   ├── obj
│   │   ├── arphdr.o
│   │   ├── ethhdr.o
│   │   ├── ip.o
│   │   ├── mac.o
│   │   └── main.o
│   └── send-arp-test
├── send-arp-test.pro
└── src
    ├── arphdr.cpp
    ├── ethhdr.cpp
    ├── getPacket.cpp
    ├── ip.cpp
    ├── mac.cpp
    └── main.cpp
````

# How to execute file

you should execute **send-arp-test**

````
$./send-arp-test <interface> <sender ip 1> <target ip 1>
````
