============================
org.bluez.ThermometerManager
============================

-------------------------------------------------------
BlueZ D-Bus Health ThermometerManager API documentation
-------------------------------------------------------

:Version: BlueZ
:Date: July 2011
:Author: Santiago Carot-Nemesio <sancane@gmail.com>
:Manual section: 5
:Manual group: Linux System Administration

.. note::

   This interface is a **legacy specification** from 2011. It is **not
   implemented** in the current Rust-based BlueZ daemon. The documentation
   is retained for historical reference only.

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.ThermometerManager1 [legacy, not implemented]
:Object path:	[variable prefix]/{hci0,hci1,...}

Methods
-------

void RegisterWatcher(object agent)
``````````````````````````````````

Registers a watcher to monitor scanned measurements.
This agent will be notified about final temperature
measurements.

Possible Errors:

:org.bluez.Error.InvalidArguments:


void UnregisterWatcher(object agent)
````````````````````````````````````

Unregisters a watcher.

void EnableIntermediateMeasurement(object agent)
````````````````````````````````````````````````

Enables intermediate measurement notifications
for this agent. Intermediate measurements will
be enabled only for thermometers which support it.

Possible Errors:

:org.bluez.Error.InvalidArguments:

void DisableIntermediateMeasurement(object agent)
`````````````````````````````````````````````````

Disables intermediate measurement notifications
for this agent. It will disable notifications in
thermometers when the last agent removes the
watcher for intermediate measurements.

Possible Errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotFound:
