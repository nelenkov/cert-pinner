Certificate pinning in Android 4.2
==================================

Sample code for the 'Certificate pinning in Android 4.2' article at 

http://nelenkov.blogspot.com/2012/12/certificate-pinning-in-android-42.html

How to use:

N.B. The app needs system permissions so it needs to be installed on a 
rooted device or the emulator.

**WARNING** Using it incorrectly may mess up certificate validation on 
your device, making it impossible to connect to certain (or all) 
secure sites. Do take a *full* system backup before using and proceed 
with caution. Do read the associated article to make sure you understand 
what the app does. 

1. Import in Eclipse and build (requires API level 17 build target and a 
recent ADT version). 
2. Mount the ```/system``` partition of your test device ```rw``` if necessary:

```
  $ su
  # mount -o rw,remount /system
```

3. Sign and export the app into this directory.
4. Run ```run.su``` to install and start on the device. 
5. Explore.

