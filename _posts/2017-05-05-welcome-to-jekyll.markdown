---
layout: post
title:  "Frida hooking android part 1"
date:   2017-05-05 23:19:33 +0200
categories: Frida
---
## **Introduction**

In this post and the next few posts we will talk about **[Frida](https://www.frida.re/)** the Dynamic Binary Instrumentation tool, I will show you some examples that highlight what Frida can do, We will work on small android applications that i wrote, the source code of this app will be available on github, so let's start.

One more thing, you should take a look first at the documentation, I will not repeat the documentation, I will show you examples that can make the documentation more understandable.

## **Installation**:

You can check the [Quick-Start](https://www.frida.re/docs/quickstart/) guide from the official documentation, and [installing the android server](https://www.frida.re/docs/android/), this should be straight forward.

You will also need [android development environment](https://developer.android.com/studio/install.html) if you will build the code yourself, or you can download the APK.

You will need root access on an android device to follow this tutorial, you may use a physical device, but i will be using an emulator(Android 6.0 x86).

I use [pycharm](https://www.jetbrains.com/pycharm/download/) as a python IDE, and i will be using python 2.7 .



## **Example #1**



```java
public class my_activity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_my_activity);
        while (true){

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            fun(50,30);
        }
    }

    void fun(int x , int y ){
        Log.d("Sum" , String.valueOf(x+y));
    }


}
```
This snippet is a part of the android code, `onCreate` will be called when the app runs, it waits for 1 second and then calls function `fun` , and repeats forever.

Function `fun` will print the sum of the two arguments (80), logs can be viewed using logcat.



![]({{site.url}}/images/1/1.PNG)

Now, we will use frida to change this result and these are the steps that we should follow:

1. start frida server
2. install the APK
3. run the APK and attach frida to the app.
4. hook the calls to function `fun` 
5. modify the arguments as we wish

starting frida server:

```powershell
PS C:\Users\11x256> adb shell
root@generic_x86:/ # /data/local/tmp/frida-server &
```

Installing the APK:

```powershell
PS C:\Users\11x256> adb install .\Desktop\app-1.apk
.\Desktop\app-1.apk: 1 file pushed. 49.0 MB/s (1573086 bytes in 0.031s)
        pkg: /data/local/tmp/app-1.apk
Success
```



Frida injects Javascript into processes so we will write Javascript code, and it has python bindings so will write python to automate frida.

```python
device = frida.get_usb_device()
pid = device.spawn(["com.example.a11x256.frida_test"])
process = device.attach(pid)
device.resume(pid)
```

This piece of code will get the usb device (which is an android emulator in my case), starts the process, attaches to it and resumes that process.

You can get the package name from the APK as follows:

```bash
remnux@remnux:~/Desktop$ apktool d app-1.apk 
remnux@remnux:~/Desktop$ grep "package" ./app-1/AndroidManifest.xml 
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.a11x256.frida_test" platformBuildVersionCode="25" platformBuildVersionName="7.1.1">

```

Now we want to write some JS code that will be injected into the running process to extract/modify the arguments of the function call.

We already know the name of the function `fun` and the class that contains it `main_activity`.

```javascript
console.log("Script loaded successfully ");
Java.perform(function x(){
    //get a wrapper for our class
    var my_class = Java.use("com.example.a11x256.frida_test.my_activity");
    //replace the original implmenetation of the function `fun` with our custom function
    my_class.fun.implementation = function(x,y){
    //print the original arguments
    console.log( "original call: fun("+ x + ", " + y + ")");
    //call the original implementation of `fun` with args (2,5)
    var ret_value = this.fun(2,5);
    return ret_value;
    }});

```

Full scripts are here:



## The result:



The function is now called with our arguments(2,5)![]({{site.url}}/images/1/2.PNG)

The output of console.log appears in the python console.

![]({{site.url}}/images/1/3.PNG)