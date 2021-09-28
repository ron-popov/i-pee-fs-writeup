# i-pee fs
## What we got
Seems like an interesting challenge, we are given some source code and and UDP (???) ip port to connect to, let's see whats up.

After having a quick look at the code and running it a couple of times, i saw that it is simply a file server.
To get data send it an index and it will send back the *DWORD* at that index, with the index shifted into the value we get, like so 
```
data_to_send := uint64(index<<32) + uint64(data[(index%dataLength)])
```

## Downloading the data
I wrote a short python function that fetches data from the server, and removes the index shifted into it, just to make my life a bit easier
```python
def get_value(index):
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.sendto(bytes(str(index), "ascii"), (REMOTE_IP, REMOTE_PORT))

	raw_value = sock.recvfrom(1024)[0].strip()
	remote_value = int(raw_value.decode("ascii"))

	actual_value = remote_value % 0x100000000

	return actual_value
```

My first though was to download all of the data to make it easier to work, but i quickly realised that it is too much to download and i will have to work smart - not hard.

Before that, i improved ```get_value``` to return the *BYTE* at the given index and not the *DWORD*, usually it makes it easier to read and work with.
After using it i also understood that it would probably help if the function had a caching mechanism, i used ```shelve``` to implement that (implementation of dict on the filesystem), now ```get_value``` looks like this :
```python
cache = shelve.open("fs_cache.bin")
def get_value(index):
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	fetch_index = int(index / 4)

	if str(fetch_index) in cache:
		actual_value = int(cache[str(fetch_index)])
		print("[-] Pulled value for {} from memory, value is {}".format(fetch_index, actual_value))
	else:
		sock.sendto(bytes(str(fetch_index), "ascii"), (REMOTE_IP, REMOTE_PORT))

		raw_value = self.sock.recvfrom(1024)[0].strip()
		remote_value = int(raw_value.decode("ascii"))

		actual_value = remote_value % 0x100000000
		cache[str(fetch_index)] = str(actual_value)

		print("[-] Got {} from remote for fetch index {}".format(hex(actual_value), hex(fetch_index)))

	value_bytes = b""
	for x in range(4):
		value_bytes += (actual_value % 0x100).to_bytes(1, byteorder="big")
		actual_value = int(actual_value / 0x100)

	cache.sync()

	return value_bytes[index % 4]
```

## Examining the data
If we cant get the entire file so let's get just the start (0x1000 bytes), it will probably be enough to understand what type of file it is and find a parser for it.
I downloaded the first 0x1000 bytes and dumped it into a file (using some python magic), then i used the ```file``` command to understand what type of file is it
```bash
┌──(kali㉿kali)-[~/DownUnder2021]
└─$ file prefix.bin
prefix.bin: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, reserved sectors 4, root entries 512, Media descriptor 0xf8, sectors/FAT 128, sectors/track 32, heads 64, sectors 131072 (volumes > 32 MB), serial number 0xf3d42729, unlabeled, FAT (16 bit)
```

oh boy...
It seems like it's a FAT16 filesystem file (Which explains why we couldn't download the entire file).
Well i need to parse it somehow, without downloading the file. So i searched for a python FAT16 parser and make it parse the remote file instead of a local file.

## Fake file class
To parse a remote file, i wrote a class that acted as a fake file, the object looked exactly the same as a file object would (function wise), but instead of reading a file, it would read the remote file.
This is what it looks like

```python
from kaitaistruct import KaitaiStream, BytesIO

class FakeFile(KaitaiStream):
	def __init__(self, remote_ip, remote_port):
		self.index = 0
		self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.remote_ip = remote_ip
		self.remote_port = remote_port
		self.cache = shelve.open("fs_cache.bin")

	def __get_value(self, index):
		fetch_index = int(index / 4)
		if str(fetch_index) in self.cache:
			actual_value = int(self.cache[str(fetch_index)])
			print("[-] Pulled value for {} from memory, value is {}".format(fetch_index, actual_value))
		else:
			self.sock.sendto(bytes(str(fetch_index), "ascii"), (self.remote_ip, self.remote_port))

			raw_value = self.sock.recvfrom(1024)[0].strip()
			remote_value = int(raw_value.decode("ascii"))

			actual_value = remote_value % 0x100000000
			self.cache[str(fetch_index)] = str(actual_value)

			print("[-] Got {} from remote for fetch index {}".format(hex(actual_value), hex(fetch_index)))

		value_bytes = b""
		for x in range(4):
			value_bytes += (actual_value % 0x100).to_bytes(1, byteorder="big")
			actual_value = int(actual_value / 0x100)

		return value_bytes[index % 4]

	def close(self):
		print("[-] Closing stream")

	def __read_range(self, a, b):
		data = b""
		for x in range(a, b):
			data += self.__get_value(x).to_bytes(1, byteorder="big")
		self.cache.sync()

		return data

	def read(self, n):
		data = b""
		for x in range(self.index, self.index+n):
			data += self.__get_value(x).to_bytes(1, byteorder="big")
		self.cache.sync()

		self.index += n
		return data

	def read_bytes(self, n):
		return self.read(n)

	def seek(self, n):
		self.index = n

	def tell(self):
		return self.index

	def pos(self):
		return self.index

	def __getitem__(self, key):
		if isinstance(key, int):
			return self.__get_value(key)
		elif isinstance(key, slice):
			return self.__read_range(key.start, key.stop)
```

## Broken FAT16 Parser
I parsing the image using Kaitai (with VFat structure), and it really helped me write the Fake File class but it wasn't really helpful because that parser didn't really suppor extracting files from the image.

## Working FAT16 Parser
After ditching Kaitai, i searched for a FAT16 parser **written in python** that could **extract files** from an image.
Luckily https://github.com/nathanhi/pyfatfs stood up to my demands.

### Insert FakeFile
I used the example to initialize the parser and well, make it parse
```python
import fs
my_fs = fs.open_fs("fat://a.bin?read_only=true")
```

But of course, i don't want it parsing it ```a.bin```, so i searched for a call to ```open``` in the source code of the library, luckily the codebase is not very big and i managed to find it quite easily at ```PyFat.py:228```

```python
self.__set_fp(open(filename, mode=mode))
```

And i changed it to 
```python
self.__set_fp(FakeFile("34.87.210.216", 1337))
```

I Ran the example code, but some BIG read requests were made to chunks the size of 0x10000.
I assumed it because the parser is probably trying to parse something i doesn't really need, so i begain looking at the code to understand the flow of parsing an image.

### Removing unnecesery reads

```open_fs``` calls ```open``` which opens the image file (FakeFile in our case), then calls ```parse_header```, ```_parse_fat``` and ```parse_root_dir```.
Using some print statements i found the culprit of the huge read requests was ```_parse_fat```

```_parse_fat:286``` Shown the following code :

```python
fats = []
for i in range(self.bpb_header["BPB_NumFATS"]):
    with self.__lock:
        self.__seek(first_fat_bytes + (i * fat_size))
        fats += [self.__fp.read(fat_size)]
```

You are probably wondering, hmmm what is the value of ```fat_size``` -> **65536**
Now, because each read request return 4 bytes, and we have implemented a caching mechanism, reading 65536 bytes translates to only 16384 read requests for each fat system, which we have 2 of -> 32768 read requests. **WAY TOO MUCH**

I tried setting it all to null bytes just to see what happens, 

```python
fats = []
for i in range(self.bpb_header["BPB_NumFATS"]):
    with self.__lock:
        self.__seek(first_fat_bytes + (i * fat_size))
        fats += [b'\x00' * fat_size]
```

That really didn't go that well :(
```
PyFATException: FREE_CLUSTER mark found in FAT cluster chain, cannot access file
```

How about just not calling ```_parse_fat``` ? I commented the call to ```_parse_fat```, and surpirisingly, didn't get any errors :D
I tried interacting with ```my_fs``` and find any interesting function i can call, but failed :(
I looked into ```parse_root_dir``` because it sound interesting and maybe it could atleast give us an path, it calls ```_fat12_parse_root_dir``` based on the FS Type (FAT16), the function parses the structure of the directories, i would love to find the dir structure but i wonder if it can do that without parsing fat...

I added a ```print(subdirs)``` before the for loop
```python
print(subdirs)
for dir_entry in subdirs:
	self.root_dir.add_subdirectory(dir_entry)
```

And surprisingly, running the example code got me a dirlist !
```
00 literal garbage ignore, 01 lol, 03 owo whats this, 03 pfp.jpg, 04 story, 05 pkfire, 07 flag.txt, pics
```

We got a path of the flag : "07 flag.txt" ! All that's left is to understand where it's content is located and read it.
I tried reading it using this code 
```python
flag_file = my_fs.openbin("07 flag.txt")
flag_file.read()
```

But got the following error
```
---------------------------------------------------------------------------
c:\users\user\appdata\local\programs\python\python39\lib\site-packages\pyfatfs\FatIO.py in read(self, size)
    149                 break
    150
--> 151         self.seek(read_bytes, 1)
    152
    153         chunks = b"".join(chunks)

c:\users\user\appdata\local\programs\python\python39\lib\site-packages\pyfatfs\FatIO.py in seek(self, offset, whence)
     80         prev_index = self.__cindex
     81
---> 82         self.__cindex = offset // self.fs.bytes_per_cluster
     83         self.__coffpos = offset % self.fs.bytes_per_cluster
     84         self.__bpos = offset

ZeroDivisionError: integer division or modulo by zero
```

```self.fs.bytes_per_cluster``` is 0, weird. Probably running  ```_parse_fat``` is required after all.
Guess we have to handle this ```FREE_CLUSTER mark``` error somehow, further inspection of the traceback shows that the culprit function is ```get_cluster_chain```, lets see what happens it when we comment ```_parse_fat```
Adding a print for ```first_cluster``` and ```len(self.fat)``` before the while loop, should be enough.

Without ```_parse_fat``` commented out, the value of ```first_cluster``` is 12315, and ```len(self.fat)``` is 32768.
Commenting out ```_parse_fat``` changed the values to 12315 for ```first_cluster``` (same value), and ```len(self.fat)``` is now 0, which means the code doesn't even enter into the while loop.

Because commenting out, does succeed in parsing the dirlist, i would keep it that way, leaving us with  ```self.fs.bytes_per_cluster=0```, to fix that, lets look at ```_parse_fat``` and see how it parses ```bytes_per_cluster``` and just comment the rest.

Looking at the code, shows that at first the function read quite a lot of data (which we changed to reading null byets), and then goes into this big and scary while loop, so i commented it out.

Leaving us with the following error 
```
---------------------------------------------------------------------------
RuntimeError                              Traceback (most recent call last)
~\Desktop\DownUnder\ipfs\use_pyfatfs.py in <module>
      3
      4 flag_file = my_fs.openbin("07 flag.txt")
----> 5 print(flag_file.read())
      6
      7 # cluster_chain = []

c:\users\user\appdata\local\programs\python\python39\lib\site-packages\pyfatfs\FatIO.py in read(self, size)
    154         chunks = b"".join(chunks)
    155         if len(chunks) != size:
--> 156             raise RuntimeError("Read a different amount of data "
    157                                "than was requested.")
    158         return chunks

RuntimeError: Read a different amount of data than was requested.
```

Well, the read fails, upen further inspection into the code of ```FatIO::read```, the number of chunks read does not match the size requested, using some more print statements, the size requested is 50 bytes, but ```len(chunks)``` is 0.
```chunks``` is appended to inside the for loop, which looks like so ```for c in self.fs.get_cluster_chain(self.__cpos)```
```get_cluster_chain``` returns a generator, so printing it doesn't really give us much, but adding a print inside the loop will show us that the code inside the loop doesn't run once !
We probably broke ```get_cluster_chain``` somehow, so let's try and fix it.

### Getting flag cluster
Messing around with ```flag_file``` object can also give us the cluster in which the flag is located - 12314, using this code snippet
```python
flag_file.dir_entry.get_cluster()
```

### Fixing ```get_cluster_chain```
```get_cluster_chain``` has a loop which probably iterates over the requested clusters, ```i``` equals the first cluster, is used as index in ```self.fat``` and then changed every iteration.
But we broke ```self.fat``` by injecting it with null bytes...
Lets fix it then, instead of inserting a lot of null bytes, i would like it to be all null bytes, except the bytes the parser requested, so i uncommented the big while loop in ```_parse_fat``` and changed the small for loop to look like so
```python
for i in range(self.bpb_header["BPB_NumFATS"]):
	with self.__lock:
		self.__seek(first_fat_bytes + (i * fat_size))
		
		flag_cluster = 12314
		temp_fat = b'\x00' * flag_cluster
		self.__seek(first_fat_bytes + (i * fat_size) + flag_cluster)
		temp_fat += self.__fp.read(0x100)
		temp_fat += (fat_size - len(temp_fat)) * b'\x00'
		fats += [temp_fat,]
```

But we still get the same error :(
Maybe the index is off ? I would like to inspect what is ```self.fat``` inside the ```get_cluster_chain``` function, so i used ```ipdb``` to do that
```python
i = first_cluster
print(first_cluster)
print(len(self.fat))
import ipdb
ipdb.set_trace()
while i <= len(self.fat):
	...
```

```
> c:\users\user\appdata\local\programs\python\python39\lib\site-packages\pyfatfs\pyfat.py(819)get_cluster_chain()
    818         ipdb.set_trace()
--> 819         while i <= len(self.fat):
    820             if min_data_cluster <= self.fat[i] <= max_data_cluster:

ipdb> len(self.fat)
32768
```

Weird, that is example half of ```fat_size```, i guess it probably has something 

