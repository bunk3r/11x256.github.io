---
layout: post
title:  "Frida hooking android part 5: Bypassing AES encryption"
date:   2017-06-28 2:00:00 +0200
categories: Frida Android-reversing
description: Bypassing android encryption , obtaining data in clear text.
tags: Frida android reverse engineering
published: true
---
## **Introduction**

In this post we will hook Java's Crypto library using frida to acquire the data in clear text and the decryption/encryption keys from an android app.



## **Example #5**



```java
package com.example.a11x256.frida_test;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class my_activity extends AppCompatActivity {
    EditText username_et;
    EditText password_et;
    TextView message_tv;
    HttpURLConnection conn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_my_activity);
        message_tv = ((TextView) findViewById(R.id.textView));
        username_et = (EditText) findViewById(R.id.editText);
        password_et = (EditText) findViewById(R.id.editText2);
        ((Button) findViewById(R.id.button)).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                send_data(username_et.getText() + ":" + password_et.getText());
            }
        });

    }

    void send_data(final String data) {
        URL url = null;
        try {
            url = new URL("http://192.168.18.134");
            final HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        DataOutputStream out = new DataOutputStream(conn.getOutputStream());
                        out.writeBytes(enc(data));
                        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        final String text = in.readLine();
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                ((TextView) findViewById(R.id.textView)).setText(text);
                                dec(text);
                            }
                        });
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    String enc(String data) {
        try {
            String pre_shared_key = "aaaaaaaaaaaaaaaa"; //assume that this key was not hardcoded
            String generated_iv = "bbbbbbbbbbbbbbbb";
            Cipher my_cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            my_cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(pre_shared_key.getBytes("UTF-8"), "AES"), new IvParameterSpec(generated_iv.getBytes("UTF-8")));
            byte[] x = my_cipher.doFinal(data.getBytes());

            System.out.println(new String(Base64.encode(x, Base64.DEFAULT)));
            return new String(Base64.encode(x, Base64.DEFAULT));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    String dec(String data) {
        try {
            byte[] decoded_data = Base64.decode(data.getBytes(), Base64.DEFAULT);
            String pre_shared_key = "aaaaaaaaaaaaaaaa"; //assume that this key was not hardcoded
            String generated_iv = "bbbbbbbbbbbbbbbb";
            Cipher my_cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            my_cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(pre_shared_key.getBytes("UTF-8"), "AES"), new IvParameterSpec(generated_iv.getBytes("UTF-8")));
            String plain = new String(my_cipher.doFinal(decoded_data));
            return plain;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return "";
    }
}
```
The application uses AES cipher in CBC mode to decrypt and encrypt data, encrypted data is to sent to a HTTP server using POST request, data received from the server is decrypted and never displayed.

The keys are hardcoded in the app, in real world applications they won't, they should be transmitted securely over the network at runtime.

So our goal is to get the crypto keys while they are being used (after being transferred from the remote servers in real world apps).



The JS code:

```javascript
console.log("Script loaded successfully 55");


Java.perform(function x() {
    var secret_key_spec = Java.use("javax.crypto.spec.SecretKeySpec");
    //SecretKeySpec is inistantiated with the bytes of the key, so we hook the constructor and get the bytes of the key from it
    //We will get the key but we won't know what data is decrypted/encrypted with it
    secret_key_spec.$init.overload("[B", "java.lang.String").implementation = function (x, y) {
        send('{"my_type" : "KEY"}', new Uint8Array(x));
        //console.log(xx.join(" "))
        return this.$init(x, y);
    }
    //hooking IvParameterSpec's constructor to get the IV as we got the key above.
    var iv_parameter_spec = Java.use("javax.crypto.spec.IvParameterSpec");
    iv_parameter_spec.$init.overload("[B").implementation = function (x) {
        send('{"my_type" : "IV"}', new Uint8Array(x));
        return this.$init(x);
    }
    //now we will hook init function in class Cipher, we will be able to tie keys,IVs with Cipher objects
    var cipher = Java.use("javax.crypto.Cipher");
    cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (x, y, z) {
        //console.log(z.getClass()); 
        if (x == 1) // 1 means Cipher.MODE_ENCRYPT
            send('{"my_type" : "hashcode_enc", "hashcode" :"' + this.hashCode().toString() + '" }');
        else // In this android app it is either 1 (Cipher.MODE_ENCRYPT) or 2 (Cipher.MODE_DECRYPT)
            send('{"my_type" : "hashcode_dec", "hashcode" :"' + this.hashCode().toString() + '" }');
        //We will have two lists in the python code, which keep track of the Cipher objects and their modes.


        //Also we can obtain the key,iv from the args passed to init call
        send('{"my_type" : "Key from call to cipher init"}', new Uint8Array(y.getEncoded()));
        //arg z is of type AlgorithmParameterSpec, we need to cast it to IvParameterSpec first to be able to call getIV function
        send('{"my_type" : "IV from call to cipher init"}', new Uint8Array(Java.cast(z, iv_parameter_spec).getIV()));
        //init must be called this way to work properly
        return cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").call(this, x, y, z);

    }
    //now hooking the doFinal method to intercept the enc/dec process
    //the mode specified in the previous init call specifies whether this Cipher object will decrypt or encrypt, there is no functions like cipher.getopmode() that we can use to get the operation mode of the object (enc or dec)
    //so we will send the data before and after the call to the python code, where we will decide which one of them is cleartext data
    //if the object will encrypt, so the cleartext data is availabe in the argument before the call, else if the object will decrypt, we need to send the data returned from the doFinal call and discard the data sent before the call
    cipher.doFinal.overload("[B").implementation = function (x) {
        send('{"my_type" : "before_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(x));
        var ret = cipher.doFinal.overload("[B").call(this, x);
        send('{"my_type" : "after_doFinal" , "hashcode" :"' + this.hashCode().toString() + '" }', new Uint8Array(ret));

        return ret;
    }
});
```



The python code

```python
import time
import frida
import json
enc_cipher_hashcodes = [] #cipher objects with Cipher.ENCRYPT_MODE will be stored here
dec_cipher_hashcodes = [] #cipher objects with Cipher.ENCRYPT_MODE will be stored here


def my_message_handler(message, payload):
    if message["type"] == "send":
        # print message["payload"]
        my_json = json.loads(message["payload"])
        if my_json["my_type"] == "KEY":
            print "Key sent to SecretKeySpec()", payload.encode("hex")
        elif my_json["my_type"] == "IV":
            print "Iv sent to IvParameterSpec()", payload.encode("hex")
        elif my_json["my_type"] == "hashcode_enc":
            enc_cipher_hashcodes.append(my_json["hashcode"])
        elif my_json["my_type"] == "hashcode_dec":
            dec_cipher_hashcodes.append(my_json["hashcode"])
        elif my_json["my_type"] == "Key from call to cipher init":
            print "Key sent to cipher init()", payload.encode("hex")
        elif my_json["my_type"] == "IV from call to cipher init":
            print "Iv sent to cipher init()", payload.encode("hex")
        elif my_json["my_type"] == "before_doFinal" and my_json["hashcode"] in enc_cipher_hashcodes:
            #if the cipher object has Cipher.MODE_ENCRYPT as the operation mode, the data before doFinal will be printed
            #and the data returned (ciphertext) will be ignored
            print "Data to be encrypted :", payload
        elif my_json["my_type"] == "after_doFinal" and my_json["hashcode"] in dec_cipher_hashcodes:
            print "Decrypted data :", payload
    else:
        print message
        print '*' * 16
        print payload


device = frida.get_usb_device()
pid = device.spawn(["com.example.a11x256.frida_test"])
device.resume(pid)
time.sleep(1)  # Without it Java.perform silently fails
session = device.attach(pid)

with open("s5.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)  # register the message handler
script.load()

raw_input()

```





## Files

[Example 4](https://github.com/11x256/frida-android-examples/tree/master/examples/4)