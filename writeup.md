# i-pee fs
Seems like an interesting challenge, we are given some source code and and UDP (???) ip port to connect to, let's see whats up.

After having a quick look at the code, we can see that it serves a file.
To get that data we need to send it an index and it will return us the data at that index, with the index shifted into it like so ```data_to_send := uint64(info.offset<<32) + uint64(data[(info.offset%dataLength)])```