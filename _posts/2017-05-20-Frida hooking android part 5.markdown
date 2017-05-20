---
layout: post
title:  "Frida hooking android part 5: Bypassing AES encryption"
date:   2017-05-20 2:29:00 +0200
categories: Frida Android-reversing
description: We will exchange data between the JS code injected into the android app and the python code.
tags: Frida android reverse engineering
published: false
---
## **Introduction**

In this post we will not use `console.log` to print data, we will `send` the data from the JS code to the python code for more processing, and then send the result back to the JS code to inject in the memory of the android application.



## **Example #4**



```java
package com.example.a11x256.frida_test;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

public class my_activity extends AppCompatActivity {
    EditText username_et;
    EditText password_et;
    TextView message_tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_my_activity);
        password_et = (EditText) this.findViewById(R.id.editText2);
        username_et = (EditText) this.findViewById(R.id.editText);
        message_tv = ((TextView) findViewById(R.id.textView));
        this.findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                if (username_et.getText().toString().compareTo("admin") == 0) {
                    message_tv.setText("You cannot login as admin");
                    return;
                }
                //hook target
                message_tv.setText("Sending to the server :" + Base64.encodeToString((username_et.getText().toString() + ":" + password_et.getText().toString()).getBytes(), Base64.DEFAULT));

            }
        });
    }
}
```
Lets say that this app has client side validation, that prevents us from entering "admin" as username, and we want to bypass that protection.

There are many ways to do this, for example we can hook the `compareTo` function and return a non-zero value, but we will use another way. 

We will hook the `setText`, send its argument to the python code, perform required changes, and then send the new argument back to the android as follows:

```javascript
console.log("Script loaded successfully ");
Java.perform(function () {
    var tv_class = Java.use("android.widget.TextView");
    tv_class.setText.overload("java.lang.CharSequence").implementation = function (x) {
        var string_to_send = x.toString();
        var string_to_recv;
        send(string_to_send); // send data to python code
        recv(function (received_json_object) {
            string_to_recv = received_json_object.my_data
        }).wait(); //block execution till the message is received
        return this.setText(string_to_recv);
    }
});
```

The argument of setText is sent to the python code, then recv function will wait for a JSON object sent from the python code.

The python code sends this JSON object as follows:

```python
import time

import frida

def my_message_handler(message, payload):
    print message
    print payload
    if message["type"] == "send":
        # print message["payload"]
        data = message["payload"].split(":")[1].strip()
        # print 'message:', message
        data = data.decode("base64")
        user, pw = data.split(":")
        data = ("admin" + ":" + pw).encode("base64")
        # print "encoded data:", data
        script.post({"my_data": data}) #send JSON object
        print "Modified data sent"

device = frida.get_usb_device()
pid = device.spawn(["com.example.a11x256.frida_test"])
device.resume(pid)
time.sleep(1)  
session = device.attach(pid)
with open("s4.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler) #register the message handler 
script.load()
raw_input()
```





## Files

[Example 4](https://github.com/11x256/frida-android-examples/tree/master/examples/4)