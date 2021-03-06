# GPAKE IoT Authentication
Comparing the performance of JPAKE+, SPEKE+, JPAKE, and SPEKE implemented over a network to see if there is any benefit in GPAKE algorithms.

## Setup the project
Two libraries will need to be added to the repository to run on your own machine. <br/>
gson library <br/>
bcprov-jdk15on <br/>
These should be able to be installed by using the Maven Script. If the script fails to install the jar files can be downloaded from the following links then add as a dependency, this can be done easily using IntelliJ. If running the code in the command line, compile using the following setup <br />
`javac -cp ".../.../*.jar;" Client.java` <br />
`javac -cp ".../.../*.jar;" Server.java` <br />
If doing it through IntelliJ (STRONGLY RECOMMENDED) the dependencies can be loaded by synchronizing the maven file by right clicking on it and clicking synchronise. <br/> 
To add the jars manually go to file->Project Structure->Modules `cmd +;` and click add jars.
https://github.com/google/gson <br/>
https://www.bouncycastle.org/latest_releases.html <br/>
The jar files have also been included in this repo for convienience. Note that code was tested and developed using the IntelliJ IDE.
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
<br/><br/>
The python implementation can be found in the pythonJPAKEPlusECDemo folder.<br/> 
To run the python implementation first install the EcPy module by running `pip3 install EcPy`<br/>
To run the program enter the following into the command line `python3 JpakePlusECDemo.py`.
### JPAKE Dynamic Pairing
To test JPAKE+ enter `:PAIR` into the dialog box on the desktop client after a group has already been established. This must be done with a new user not part of the group. This feature is not currently available on the android implementation

### JPAKE Dynamic Removal
This feature is only available on the desktop version. Create a group with greater than 3 participants then disconnect a user, a group should be reestablished with the remaining users. 

# Results
The results gathered so far can be viewed in the logs folder. This contains the logs output from each of the testing devices and the Jupyter Notebook file used to perform the data analytics. The graphs evaluating performance can be viewed here.
Run using `jupyter notebook` in the logs folder.
