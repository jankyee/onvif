#
# VLC-Qt Simple Player
# Copyright (C) 2015 Tadej Novak <tadej@tano.si>
#

TARGET      = simple-player
TEMPLATE    = app
CONFIG 	   += c++11

QT         += widgets

SOURCES    += main.cpp \
    SimplePlayer.cpp \
    duration.c \
    sha1.c \
    soapC.c \
    soapClient.c \
    stdsoap2.c \
    cap.c

HEADERS    += SimplePlayer.h \
    cap.h \
    sha1.h \
    include/onvif.h \
    include/soapH.h \
    include/soapStub.h \
    include/stdsoap2.h \
    include/wsdd.h

FORMS      += SimplePlayer.ui

LIBS       += -lVLCQtCore -lVLCQtWidgets


# Edit below for custom library location
#LIBS       += -L/Users/tadej/workspace/tanoprojects/install/vlc-qt/lib -lVLCQtCore -lVLCQtWidgets
#INCLUDEPATH += /Users/tadej/workspace/tanoprojects/install/vlc-qt/include
INCLUDEPATH += ./include
