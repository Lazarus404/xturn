Xirsys TURN Server in Elixir
=====

This is an implementation of a TURN server in Elixir (based on the xstun server project).  It was originally written in Erlang and ported in 2014 when we migrated our other code.  It's never been in production and, indeed, needs more work for that.  However, it's a great little personal project and fun to work with.  It works nicely with WebRTC.

Supported Features
===

- TCP, UDP, TLS and DTLS supported
- Full TURN RFC5766 support (except rotating nonce)
- Full STUN RFC3489 support
- Simple user / pass storage with Web API interface

Future Plans
===

- Create a rotating nonce
- Get a decent user credential store working with decent timeout capability (it's a little limited at the moment).
- Get RTP and RTCP working with a new MCU or SFU functionality
- Implement stream recording to file
- Implement third party streaming server connectivity
- Full support for IPv6
- TCP Allocations (connect command)

Changelog
===
02-07-2018 - Get working with test.webrtc.org

26-06-2018 - Add DTLS support

21-09-2014 - Convert to Elixir

14-12-2013 - Initial working implementation in Erlang

Contact
===
For questions or suggestions, please email lee@xirsys.com or experts@xirsys.com

Copyright
===
This TURN server has been made open source for use by non-commercial groups and individuals by Xirsys LLC. However, if you wish to use this application or any of the code contained in a commercial application, please send us an email.