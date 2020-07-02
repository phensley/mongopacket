# mongopacket

This is a quick hack to parse MongoDB wire messages out of packet captures, attempting to resynchronize streams to tolerate some packet loss. It was built in support of an effort to diagnose issues with MongoDB

WARNING: This has only been tested against a few specific packet captures for my environment. At this time it is not a general-purpose tool.

It corrects an issue where requestID and responseTo values generated by our database are full uint32, not int32 as MongoDB's wire protocol documentation states.

