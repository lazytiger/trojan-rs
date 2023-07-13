# 异步smoltcp

## 几个关键参数的解析
* MTU 这个就是传统意义上的MTU
* channel_buffer_size 即所有可以buffer的最大响应数
* tcp_rx_buffer_size 即tcp的读缓冲栈大小，至少要大于一个MTU
* tcp_tx_buffer_size 即tcp的写缓冲栈大小，至少要大于一个MTU，且小于channel_buffer_size*MTU，否则就有可能出现由于缓冲区不足而被断开连接的情况
* udp_rx_buffer_size 参考tcp
* udp_tx_buffer_size 参考tcp