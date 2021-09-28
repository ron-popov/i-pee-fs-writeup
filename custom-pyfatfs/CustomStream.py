import socket
import shelve

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
			# print("[-] Pulled value for {} from memory, value is {}".format(fetch_index, actual_value))
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
		print("[-] Performing a sliced read of {}->{}".format(a, b))

		data = b""
		for x in range(a, b):
			data += self.__get_value(x).to_bytes(1, byteorder="big")
		self.cache.sync()

		return data

	def read(self, n):
		data = b""
		print("[-] Performing read for {} values".format(hex(n)))
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
