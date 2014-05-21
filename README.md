IRMA card
=========

This is the smart card application used by the I Reveal Your Attributes (IRMA) project to issue,
reveal and manage attributes [1]. 

#### 1. Obtaining cards

IRMA rely on MULTOS cards. Developers and users can order developer cards through MULTOS
international http://www.multosinternational.com/contact-us.aspx.

#### 2. Compiling the source code of IRMA

It is possible to load the last IRMA image into the card without compiling the
source code (Step 3). However, we describe how to compile the source code in this
section. The MULTOS SDK, Smartdeck, is only available for Windows. It can be downloaded from
https://app.multos.com/smartdeck.html.

All the toolset for compiling, examining cards and loading applications should be included in the
user PATH. Afterwards, clone the IRMA source code and compile the smart card application from the
command line. This can be done using [cygwin](http://www.cygwin.com/) and make:

```
$ git clone https://github.com/credentials/irma_card
$ cd irma_card/
$ make
```

From the output of the linker we can get the RAM space we need to
include in the MULTOS loader (528 bytes in this case):

```
mkdir -p bin
hcl -ansi -O -Iinclude -DML3 -DRSA_VERIFY -DSIMULATOR -g src/IRMAcard.c src/verification.c src/RSA.c src/random.c src/AES.c src/debug.c src/math.c src/utils.c src/auth.c src/SM.c src/issuance.c src/CHV.c src/logging.c src/ASN1.c -o bin/IRMAcard.simulator-ML3.hzx
hcl -ansi -O -Iinclude -DML3 -DRSA_VERIFY -Falu src/IRMAcard.c src/verification.c src/RSA.c src/random.c src/AES.c src/debug.c src/math.c src/utils.c src/auth.c src/SM.c src/issuance.c src/CHV.c src/logging.c src/ASN1.c -o bin/IRMAcard.smartcard-ML3.alu
code: 11434, static: 31889, session: 528
```
#### 3. Loading IRMA in a MULTOS developer card

In MULTOS, the smart card applications are loaded using the MUtil tool. It can be downloaded
from http://www.multos.com/uploads/MUtil.zip.

In order to load an application in the card we must first copy the AID into MUtil. In the case
of IRMA this is specified in the .aif file of the card/ directory for the last available version.
Moreover, we must include the RAM space that will be reserved for session data in the application(Section 2).

#### 4. Using your IRMA card

The first you thing you can do is to change your credential and administration PINs using
[https://github.com/credentials/silvia](Silvia). Then, you can generate an issuer keypair and
start issuing and verifying credentials using the examples from https://github.com/credentials/irma_configuration or create your own credentials.

#### 5. References

[1] http://www.irmacard.org/
