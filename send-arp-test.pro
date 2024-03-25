TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

INCLUDEPATH += ./include

DESTDIR = ./out

OBJECTS_DIR = ./out/obj

SOURCES += \
    src/arphdr.cpp \
    src/ethhdr.cpp \
    src/ip.cpp \
    src/mac.cpp \
    src/getPacket.cpp \
    src/main.cpp

HEADERS += \
    include/arphdr.h \
    include/ethhdr.h \
    include/ip.h \
    include/getPacket.h \
    include/mac.h
