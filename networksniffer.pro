#-------------------------------------------------
#
# Project created by QtCreator 2012-06-11T00:21:49
#
#-------------------------------------------------

QT       += core gui

TARGET = networksniffer
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    capture.cpp \
    cap_optdialog.cpp \
    capthread_data.cpp \
    filter_grammer.cpp

HEADERS  += mainwindow.h \
    capture.h \
    packethead.h \
    datatype.h \
    cap_optdialog.h \
    capthread_data.h \
    filter_grammer.h

win32:INCLUDEPATH += D:\\Libs\\WpdPack\\Include
win32:LIBS += "D:\\Libs\\WpdPack\\Lib\\Packet.lib"
win32:LIBS += "D:\\Libs\\WpdPack\\Lib\\wpcap.lib"

