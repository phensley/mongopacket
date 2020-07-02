# mongopacket

This is a quick hack to parse MongoDB wire messages out of packet captures, attempting to resynchronize streams to tolerate some packet loss. It was built in support of an effort to diagnose issues with MongoDB

**WARNING**: This is not a general-purpose tool. There are many hard-coded values, and this has only been tested against a few specific packet captures for my environment.

Our database generates requestID and responseTo values that are `uint32`, not `int32` as MongoDB's wire protocol documentation states. This impl treats those values as `uint32`.

