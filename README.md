TCP Project
===========
**Independent
Study Goals/Objectives**

The
goal for this independent study is to get a more in-depth view on how
the transport layer works, specifically the Transmission Control
Protocol (TCP). A great way to do this would be to build my own
implementation of TCP. It would require me to research, design,
program and test my library which would allow me to gain the
knowledge of how reliable data transfer works in the back end. Once
this is done, I will go one step further and create my own hypothesis
pertaining to TCP and experiment with my library. Then I will make my
final conclusions to wrap up what I have learned from the experiment.
By following the schedule below, I will learn a great deal about TCP
and the transport layer over the course of the semester.

**Schedule**

1. Start by setting up the
    environment to use for development and install any virtual machines
	needed for testing. Then research tools that will help with
	development and pick the best language for the project. Review
	properties of TCP before implementing any code. 

1. Begin implementing the library
	by adding the ability of sending raw packets between two clients. 

1. **Deliverable**: Program an
	interface to write packet headers for creating a UDP packet. Then
	send those packets between two clients. 

1. Implement TCP packet headers.
	Create TCP packets to send between two clients. 

1. Implement
	ability to establish and terminate a connection between two peers. 

1. **Deliverable**: Implement
	reliable transfer protocol by making sure the packets arrive in
	order and that no packets are lost. Start by sending packets in a
	Stop and Wait fashion and then add in the ability to send them in
	parallel. 

1. Add in error detection of
	packets by examining the checksum of each received packet. 

1. Add Flow Control to the library to avoid having the sender send data too fast for the TCP receiver
	to receive. 

1. **Deliverable**: Implement
	Congestion Control – this includes implementing the Slow-Start,
	Congestion Avoidance, and Fast Recovery algorithms. Begin testing
	against another implementation of TCP. 

1. **Deliverable**: Make a
	hypothesis about TCP and what would happen if some property changed.
	Then experiment by making the appropriate change to the library.
	Test and analyze the result to make a conclusion about the
	hypothesis.