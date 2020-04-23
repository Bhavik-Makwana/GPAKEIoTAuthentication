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

### JPAKE+
To test JPAKE+ enter `:START` into the dialog box on the desktop client once three users are connected, each clients latency will be output to the console. On the Android client, press the JPAKE+. After pressed on the first device, you will have 5s left to connect the other devices to perform the group authentication.

### SPEKE+
To test SPEKE+ enter `:SPEKE` into the dialog box on the desktop client once three users are connected, each clients latency will be output to the console. On the Android client, press the JPAKE+. After pressed on the first device, you will have 5s left to connect the other devices to perform the group authentication.

### JPAKE+ EC
To test JPAKE+ enter `:EC` into the dialog box on the desktop client once three users are connected, each clients latency will be output to the console. On the Android client, press the JPAKE+. After pressed on the first device, you will have 5s left to connect the other devices to perform the group authentication.

### JPAKE Dynamic Pairing
To test JPAKE+ enter `:PAIR` into the dialog box on the desktop client after a group has already been established. This must be done with a new user not part of the group. This feature is not currently available on the android implementation

### JPAKE Dynamic Removal
This feature is only available on the desktop version. Create a group with greater than 3 participants then disconnect a user, a group should be reestablished with the remaining users. 

# Results
The results gathered so far can be viewed in the logs folder. This contains the logs output from each of the testing devices and the Jupyter Notebook file used to perform the data analytics. The graphs evaluating performance can be viewed here.
Run using `jupyter notebook` in the logs folder.
