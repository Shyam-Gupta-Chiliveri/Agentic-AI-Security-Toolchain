# ISO/SAE 21434 concepts (original notes — not the standard text)

This file is a short original summary of publicly discussed process ideas. It is **not** a copy of ISO/SAE 21434. Do not treat it as the standard.

## Item definition
The “item” here is an ECU that speaks SAE J1939 on CAN, including the transport protocol (TP.CM / TP.DT) used to move payloads larger than 8 bytes.

## Cybersecurity property
Integrity and availability of the J1939 transport parser: a malformed sequence must not write outside the TP buffer or take the ECU into an undefined state.

## Threat
An attacker on the CAN bus (physical access, compromised gateway, or a second ECU) sends crafted TP.CM and TP.DT frames.

## Weakness class
CWE-787 / CWE-190 / CWE-20 in the implementation of the communication item.

## Work product (portfolio mapping)
A finding in this toolchain is a *candidate weakness* with a CWE and a suggested fix. It is not a complete TARA, CAL assignment, or CSMS artifact.

## Residual risk note
Static analysis and a short AFL++ campaign are not a substitute for a full 21434-aligned verification program.
