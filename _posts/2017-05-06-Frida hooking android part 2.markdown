---
layout: post
title:  "Frida hooking android part 2"
date:   2017-05-06 16:00:00 +0200
categories: Frida
description: I will show you how to deal with method overloading and non-primitive datatypes.
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

I added two new functions:

1. `fun` that accepts a String as input and returns another String, so now we have two functions with the same but different signatures(function overloading).
2. `secret` which is not called anywhere in the program.



If we ran the script from the previous example, it will fail silently, in order to see the error message we have to handle messages sent form our js code to our python code by adding the following python code.

```python
#python code
def my_message_handler(message , payload): #define our handler
	print message
	print payload
...
script.on("message" , my_message_handler) #register our handler to be called
script.load()

```

We define a function to be called when the js code sends a message to the python code, and register this function.

Now run the code again and you will get this error message

```json
{u'columnNumber': 1, u'description': u"Error: fun(): has more than one overload, use .overload(<signature>) to choose from:\n\t.overload('java.lang.String')\n\t.overload('int', 'int')",...

```

It says the there is more than one function named `fun` and that we should use either `fun.overload('java.lang.Stirng')` or `fun.overload('int' , 'int')`



To handle this situation -Which is so common in obfuscated android code- we will use the frida's overload method as follows.

```
my_class.fun.overload("int" , "int").implementation = function(x,y){ //hooking the old function

....

my_class.fun.overload("java.lang.String").implementation = function(x){ //hooking the new function

```

The first line hooks the function `fun` that has two int parameters, the second line hooks the function that has a String parameter.

Now lets see how can we change the string argument, [String](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html) datatype is a non primitive datatype, which means that it is a class that has methods and attributes.

There are two ways to create a String object in java:

- `String test = "this is test string";`
- `String test = new String("this is also a string test");`

Both methods are equivalent here, but in other cases there will be only one way (using `new` operator).

```javascript
//javascript code
var string_class = Java.use("java.lang.String"); // get a JS wrapper for java's String class

my_class.fun.overload("java.lang.String").implementation = function(x){ //hooking the new function
  console.log("*************************************");
  var my_string = string_class.$new("My TeSt String#####"); //creating a new String by using `new` operator 
  console.log("Original arg: " +x );
  var ret =  this.fun(my_string); // calling the original function with the new String, and putting its return value in ret variable
  console.log("Return value: "+ret);
  console.log("*************************************");
  return ret;
};
```

Now lets assume that we want to call function `secret`, it is not being called from the `onCreate` function, so hooking calls to it would be useless.

But we called the `new` operator in ` String` class, so we can use the same method to call it, right? No, in the case of the `new` operator, we created a new object from `String` class, but now, we don't want to create a new instance of our `my_activity` class, we want to **find** the instance that is already created in memory, and call its `secret` function.

Frida offers `Java.choose(className, callbacks)` which will find all the instances created from the specified class, lets see an example:

```javascript
#Javascript code
Java.choose("com.example.a11x256.frida_test.my_activity" , {
  onMatch : function(instance){ //This function will be called for every instance found by frida
    console.log("Found instance: "+instance);
    console.log("Result of secret func: " + instance.secret());
  },
  onComplete:function(){}

});
```

This will print the following:

```
Found instance: com.example.a11x256.frida_test.my_activity@9600a96
Result of secret func: @@@###@@@
```

We called `secret` as soon as we could, so variable `total` was not modified yet.

That's enough for this tutorial, we will control exactly when to call `secret` function in the next tutorial.



## Files

[example 2](https://github.com/11x256/frida-android-examples/tree/master/examples/2)