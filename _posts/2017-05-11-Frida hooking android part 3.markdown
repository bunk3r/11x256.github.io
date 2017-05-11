---
layout: post
title:  "Frida hooking android part 3"
date:   2017-05-11 3:14:00 +0200
categories: Frida
description: Using Frida's RPC to communicate with the hooked android application.
---
## **Introduction**

In the previous post, We were able to call function `secret` as soon as we attach our JS script into the target application process,in this tutorial we will be able to call `secret` multiple times, using Frida's RPC (Remote Procedure Call).



## Example #3

```java
package com.example.a11x256.frida_test;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

public class my_activity extends AppCompatActivity {
    private String total = "@@@###@@@";

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
            Log.d("string" , fun("LoWeRcAsE Me!!!!!!!!!"));
        }
    }

    void fun(int x , int y ){

        Log.d("Sum" , String.valueOf(x+y));
    }

    String fun(String x){
        total +=x;
        return x.toLowerCase();
    }

    String secret(){
        return total;
    }


}
```

It is the same android code as example #2, differences will be in the JS and python codes.

```javascript
//Javascript code
console.log("Script loaded successfully ");

function callSecretFun() { //Defining the function that will be exported
    Java.perform(function () { //code that calls `secret` function from the previous example

        Java.choose("com.example.a11x256.frida_test.my_activity", {
            onMatch: function (instance) {
                console.log("Found instance: " + instance);
                console.log("Result of secret func: " + instance.secret());
            },
            onComplete: function () { }

        });

    });


}
rpc.exports = {
    callsecretfunction: callSecretFun //exporting callSecretFun as callsecretfunction
  // the name of the export (callsecretfunction) cannot have  neither Uppercase letter nor uderscores.


};
```

The JS code defines a function `callSecretFun` that we will call from the python code to call `secret` function from our Android app.

```python
import time

import frida


def my_message_handler(message, payload):
    print message
    print payload


device = frida.get_usb_device()
pid = device.spawn(["com.example.a11x256.frida_test"])
device.resume(pid)
time.sleep(1)  # Without it Java.perform silently fails
session = device.attach(pid)
with open("s3.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)
script.load()

command = ""
while 1 == 1:
    command = raw_input("Enter command:\n1: Exit\n2: Call secret function\nchoice:")
    if command == "1":
        break
    elif command == "2":
        script.exports.callSecretFunction()

```

These are the changes in the python code, i added an infinite loop to read input from the user, typing "2" will call the secretfunction, which will execute `secret` from the android app and will print its return value. 



Output:

```
Script loaded successfully 
Enter command:
1: Exit
2: Call secret function
choice:2
Found instance: com.example.a11x256.frida_test.my_activity@dfbf782
Result of secret func: @@@###@@@LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!
Enter command:
1: Exit
2: Call secret function
choice:2
Found instance: com.example.a11x256.frida_test.my_activity@dfbf782
Result of secret func: @@@###@@@LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!
Enter command:
1: Exit
2: Call secret function
choice:2
Found instance: com.example.a11x256.frida_test.my_activity@dfbf782
Result of secret func: @@@###@@@LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!LoWeRcAsE Me!!!!!!!!!
Enter command:
1: Exit
2: Call secret function
choice:
Process finished with exit code 1
```

We can improve the performance of the previous JS code by saving the objects found by searching the heap in an array, instead of searching the heap on every call, and since no new objects of `my_activity` class are created, we don't have to update the array.

```javascript
//javascript code
console.log("Script loaded successfully ");
var instances_array = [];
function callSecretFun() {
    Java.perform(function () {
        if (instances_array.length == 0) { // if array is empty
            Java.choose("com.example.a11x256.frida_test.my_activity", {
                onMatch: function (instance) {
                    console.log("Found instance: " + instance);
                    instances_array.push(instance)
                    console.log("Result of secret func: " + instance.secret());
                },
                onComplete: function () { }

            });
        }
        else {//else if the array has some values
            for (i = 0; i < instances_array.length; i++) {
                console.log("Result of secret func: " + instances_array[i].secret());
            }
        }

    });


}
rpc.exports = {
    callsecretfunction: callSecretFun


};
```



## Files

[example 3](https://github.com/11x256/frida-android-examples/tree/master/examples/3)