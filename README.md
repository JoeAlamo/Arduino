# Arduino - biometric authentication

> #### WARNING: THIS PROJECT IS PURELY FOR EDUCATIONAL PURPOSES. NONE OF THE CRYPTOGRAPHY HAS BEEN VERIFIED OR TESTED BY AN EXPERT THIRD PARTY. I ASSUME NO RESPONSIBILITY IF CODE FROM THIS PROJECT IS USED IN PRODUCTION SYSTEMS.

## Overview

This repository contains several sub-projects (or sketches) related to my final year project I completed at university.

My final year project was the development of a product allowing you to log in to a website using your fingerprint and username/password.

A full multi-factor biometric authentication system was developed, including a prototype biometric authentication device.

## Process

![Multi-factor Biometric Authentication](http://i.imgur.com/0c6DwbZ.png)

This repository contains code relating to step 1 and 2 shown above. View [this repository for code relating to the other stages and an in depth explanation](https://github.com/JoeAlamo/BiometricAuthSite). 

**The full authentication process in brief:**

The user scans their fingerprint on a [fingerprint sensor](https://www.adafruit.com/product/751) connected to an [Arduino](https://www.arduino.cc/) device. The user's fingerprint would have been previously enrolled on the device. If the fingerprint matches, a set of symmetric pre-shared cryptographic keys are released. 

These keys are then used in a bespoke double challenge-response authentication protocol occurring in a RESTful fashion using JSON over HTTP. This involves performing numerous cryptographic actions on a low resource Arduino device (no HTTPS, no asymmetric crypto) to achieve mutual authentication between the user and the remote server. As the cryptographic keys used in the protocol are only ever made available by the user scanning their fingerprint, this verifies the identity of the user biometrically.

With biometric authentication achieved, the user must then navigate to the website and log in to the system using their username and password within 30 seconds to log in successfully.

## Contents of repository

### Secure Authentication Protocol version 3 (SAPv3) code

This [section](https://github.com/JoeAlamo/Arduino/tree/master/SAP%20version%203/SAPv3) contains code for SAPv3. This is the completed version of the authentication protocol. View [this repository for an indepth explanation of SAPv3](https://github.com/JoeAlamo/BiometricAuthSite)

### Lightweight Cryptography Tests

This [section](https://github.com/JoeAlamo/Arduino/tree/master/Lightweight%20Cryptography) contains code used for testing numerous lightweight encryption ciphers, hashing functions used within HMAC constructs and Authenticated Encryption with Associated Data ciphers. By running these comparisons and drawing on external resource, the most lightweight cryptography appropriate for the project was selected.


