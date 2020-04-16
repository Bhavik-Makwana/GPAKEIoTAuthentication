# GPAKEIoTAuthentication
Comparing the performance of JPAKE+, SPEKE+, JPAKE, and SPEKE implemented over a network to see if there is any benefit in GPAKE algorithms.

## Setup the project
Two libraries will need to be added to the repository to run on your own machine.
gson library
bcprov-jdk15on
These should be able to be installed by usinng the Maven Script.

## Run the code
Run the server file. This server is compatible with the GPAKEAndroidClient project or can be used with the in-built client in this repository.
Run the client and connect to localhost if using the desktop client.
To connect using the Android client find the host systems ipv4 address and make sure the device is on the same network as the server.

Ensure a minimum of 3 devices are connected to the network before an algorithm is run otherwise it will raise an exception.

