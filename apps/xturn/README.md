XirSys TURN Server in Elixir
=====

This is an implementation of a TURN server in Elixir (based on the xstun server project).  It was originally written in Erlang and ported in 2014 when we migrated our other code.  It's never been in production and, indeed, needs lots more work for that.  However, it's a great little personal project and fun to work with.  It works nicely with WebRTC.

Future Plans
===

- get a decent user credential store working with decent timeout capability (it's a little flimsy at the moment).
- get RTP and RTCP working with a new MCU or SFU functionality
- implement stream recording to file
- implement third party streaming server connectivity
- DTLS?
