---
layout: post
title:  "Frida hooking android part 2"
date:   2017-05-06 16:00:00 +0200
categories: Frida
---
## **Introduction**

In the previous post, i showed you how to intercept function calls ,log and modify the arguments, we will repeat this again in this post but with different argument types (primitive and non-primitive), and  i will show you how to deal with method overloading. so let's start.



## Example #2

```java
package com.example.a11x256.frida_test;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

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
            Log.d("string" , fun("LoWeRcAsE Me!!!!!!!!!"));
        }
    }

    void fun(int x , int y ){

        Log.d("Sum" , String.valueOf(x+y));
    }

    String fun(String x){

        return x.toLowerCase();
    }

}

```

