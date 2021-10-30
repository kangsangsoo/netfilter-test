# netfilter-test

> sudo iptables -F   
> sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0   
> sudo iptables -A INPUT -j NFQUEUE --queue-num 0   
> sudo ./netfilter-test test.gilgil.net

![실행화면](https://user-images.githubusercontent.com/63638850/139533935-42dbef2f-b971-430c-8ea2-3acbabf2f730.PNG)
