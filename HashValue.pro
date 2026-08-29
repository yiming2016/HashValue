CONFIG   += qt

## Default build is release
CONFIG   -= debug
CONFIG   += release

QT       += core gui
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = HashValue
TEMPLATE = app
VERSION = 1.0.0
DEFINES += APP_VERSION=\\\"$$VERSION\\\"

SOURCES += src/main.cpp \
           src/mainwindow.cpp \
           src/2johnformats.cpp

HEADERS += src/mainwindow.h \
           src/2johnformats.h \
           src/hashcathelper.h

RESOURCES += resources/resources.qrc
RC_ICONS = resources/icons/logo.ico
CODECFORTR = UTF-8
