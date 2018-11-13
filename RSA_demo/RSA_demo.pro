TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp \
    rsa_utility.cpp \
    rsa2_utility.cpp


LIBS += -lcrypto -fno-stack-protector

HEADERS += \
    rsa_utility.h \
    rsa2_utility.h
