#!/bin/sh

adb push cert-pinner.apk /sdcard/
adb shell su -c 'rm /system/app/cert-pinner.apk'
adb shell su -c 'cp /sdcard/cert-pinner.apk /system/app/'
sleep 5
adb shell am start org.nick.certpinner/.MainActivity

