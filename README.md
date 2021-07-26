### Alastor is a tool which makes use of [BGP hijacking](https://en.wikipedia.org/wiki/BGP_hijacking), redirecting packets leaving other [AS](https://en.wikipedia.org/wiki/Autonomous_system_%28Internet%29)s once you have access to their neighbours. It requires the [WinPCap Network Driver](https://www.winpcap.org/default.htm) to run.
## Alastor can be downloaded [here](https://github.com/jptr218/alastor/raw/main/alastor.exe) (you will need to run it from the the neighbouring BGP router that you have access to)
### Usage:

### `alastor [target BGP router] [old destination] [current ASN] [current TCP sequence number]`
