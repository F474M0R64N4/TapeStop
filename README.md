# TapeStop
The assistant to search of bottlenecks in the virtual machine

## Tested on the machine
Windows 10, IDA Pro 7.5
Plug-in for 64 bits

Oreans Code Virtualizer

- FISH64 White VM

## Shortcut

To use a plug-in it is necessary to click everything two keys.
The first to register to break points.
The second to jump to the unprotected place.

To register all points of a stop| To enter the unprotected area 
--- | ---
F10 | F3

## Installation

Visual Studio will expect the environment variable IDADIR to resolve to your IDA 7.5 installation directory.

Visual Studio will also expect the SDK to be located at %IDADIR%\idasdk.
Make sure these folders resolve in Windows properly before attempting to build the project.