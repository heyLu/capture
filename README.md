# capture - which programs are doing (which kind of) network on my computer

```
$ ./capture -h
Usage of ./capture:
  -a string
        address to listen on for ui (default "localhost:1234")
  -f string
        .pcap file to read from
  -i string
        interface to read from (default "lo")
```

To collect useful stats, you will want to run against your actual
network interface, which for me is `./capture -i wlp3s0`.  (You can list
the available interfaces using `ip link show`.)

- [ ] domains per program
- [x] tx/rx bytes per host/domain
- [x] tx/rx bytes per host/domain domain per program

Stats are collected on a per-program basis, and can be viewed at <http://localhost:1234>.

They look like this:

```
total
  packets tx: 10716, packets rx: 12406, bytes tx:  983kb, bytes rx:   10mb

/home/lu/t/firefox/firefox-bin ===========================================

*.github.com (140.82.113.26:443)
  packets tx:    17, packets rx:    21, bytes tx:    1kb, bytes rx:    1kb
github.com (140.82.121.4:443)
  packets tx:   394, packets rx:   468, bytes tx:   54kb, bytes rx:  381kb
*.github.com (140.82.121.5:443)
  packets tx:   141, packets rx:   109, bytes tx:   82kb, bytes rx:   19kb
fra24s02-in-f10.1e100.net. (142.250.74.202:443)
  packets tx:    18, packets rx:    14, bytes tx:    2kb, bytes rx:    2kb
www.github.com (185.199.108.133:443)
  packets tx:    23, packets rx:    17, bytes tx:    2kb, bytes rx:    6kb
*.githubassets.com (185.199.109.154:443)
  packets tx:    96, packets rx:    65, bytes tx:    7kb, bytes rx:   34kb
www.github.com (185.199.111.133:443)
  packets tx:   653, packets rx:   817, bytes tx:   39kb, bytes rx:  905kb
*.gravatar.com (192.0.73.2:443)
  packets tx:    41, packets rx:    29, bytes tx:    3kb, bytes rx:   12kb
ec2-44-229-115-174.us-west-2.compute.amazonaws.com. (44.229.115.174:443)
  packets tx:     3, packets rx:     4, bytes tx:    226, bytes rx:    270
*.telemetry.mozilla.org (44.235.28.153:443)
  packets tx:    25, packets rx:    18, bytes tx:    8kb, bytes rx:    4kb
*.telemetry.mozilla.org (52.34.72.48:443)
  packets tx:    23, packets rx:    21, bytes tx:    2kb, bytes rx:    4kb
*.telemetry.mozilla.org (52.89.206.61:443)
  packets tx:    23, packets rx:    20, bytes tx:    2kb, bytes rx:    4kb
```
