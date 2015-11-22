####7. Allowing for Inexpensive U2F Devices
the Key Handle can 'store'(i.e., contain) the private key for the origin and the hash of the origin encrypted with a 'wrapping' key known only to the U2F device secure element.
可见在U2F中，Key Handle并不存储任何特定用户相关的东西（username什么的），这是跟UAF不一样的地方。因此会有多个User share一个U2F设备，同一个Account注册了多个U2F设备。

####9. Client Malware Interactions with U2F Devices
U2F设备可以直接从用户空间的client访问，所以U2F是没有ASM层的？

####15. Expanding U2F to Non-browser Apps
这里U2F对AppID的处理似乎也与UAF不一样。