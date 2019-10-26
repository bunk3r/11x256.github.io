---
layout: post
title:  "Things that i forget"
date:   2019-10-15 1:03:00 +0200
categories: Notes
description: Things that I cannot remember usually 
tags: Frida android reverse engineering
published: true
---
## **Introduction**

This is post will host things that i usually write from scratch every time i need them.

**POWERSHELL**

- Read sysmon logs

  ```powershell
  Get-winevent -logname "Microsoft-Windows-Sysmon/Operational"
  ```

  





**IDA PYTHON** 



**PYTHON 3**

XOR data in file with a key.

```python
def xor_file(file_path, key_bytes):
	fin = open(file_path, 'rb')
	temp = bytearray(fin.read())
	fin.close()
	# if the key is of type "string"
	if type(key_bytes) == type(""):
		#convert ascii string to bytes
		key_bytes = list(map(ord , key_bytes))

	for i in range(len(temp)):
		temp[i] ^= key_bytes[i % len(key_bytes)]
	return temp


print(xor_file('a.bin' , 'AAAA1234'))
```

