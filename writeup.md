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

### Example code
Reading a file from a FAT16 fs using pyfatps looks like this, i used this as a sample
```python
import fs
my_fs = fs.open_fs("fat://a.bin?read_only=true")
```

### Using FakeFile instead of real file
Inserting FakeFile instead of a real file was quite easy, searching for a call to ```open``` in the source code of the library didn't lead up to that much result, the relavent one is at ```PyFat.py:228ish``` (the "ish" is becuase i made a lot of changes to the code and the line number will change)

```python
self.__set_fp(open(filename, mode=mode))
```

And i changed it to 
```python
self.__set_fp(FakeFile("34.87.210.216", 1337))
```

### Interesting functions
The functions were the most interesting were :
* ```PyFat::open``` - initialized an image and parses the interesting stuff (headers and important sections
* ```PyFat::_parse_fat``` - parses a lot of data at the beginning of the image, this function had some changes to reduce the number of read requests
* ```PyFat::get_cluster_chain``` - reads a chain of clusters from the file, this function wasn't really changed but she raised quite a lot of exceptions, that had to be resolved

### Getting data about flag file
```open_fs``` calls ```open``` which opens the image file (FakeFile in our case), then calls ```parse_header```, ```_parse_fat``` and ```parse_root_dir```.

```_parse_fat``` took a lot of time to run so i commented it out, and somehow the parser didn't really break.
I could get a list of files, and some metadata about them.
I got a dirlist by printing the ```subdirs``` object inside the function ```_fat12_parse_root_dir```

```
00 literal garbage ignore, 01 lol, 03 owo whats this, 03 pfp.jpg, 04 story, 05 pkfire, 07 flag.txt, pics
```

We got a path of the flag : "07 flag.txt" ! All that's left is to understand where it's content is located and read it.
This can be done using the code
```python
flag_file = my_fs.openbin("07 flag.txt")
flag_file_cluster = flag_file.dir_entry.get_cluster() #12314
```

Reading the file is done using
```python
flag_file.read()
```
but this didn't go so well...
Now i tried understanding why ```_parse_fat``` tried to read so much data, and how to make it read only the interesting data


### Removing big reads
I saw that the parser was trying to read a lot of data when initialzing, using some print statements i found the culprit of the huge read requests was ```_parse_fat```

The first section of ```_parse_fat``` contains this for loop, which reads ```fat_size``` bytes (64K) * ```NumFATS``` (2), this is a lot of data to read so i changed it to only read the data relavent to the 

```python
fats = []
for i in range(self.bpb_header["BPB_NumFATS"]):
    with self.__lock:
        self.__seek(first_fat_bytes + (i * fat_size))
        fats += [self.__fp.read(fat_size)]
```

You are probably wondering, hmmm what is the value of ```fat_size``` -> **65536**
Now, because each read request return 4 bytes, and we have implemented a caching mechanism, reading 65536 bytes translates to only 16384 read requests for each fat system, which we have 2 of -> 32768 read requests. **WAY TOO MUCH**

So i changed it only read the cluster of the flag_file (12314)


