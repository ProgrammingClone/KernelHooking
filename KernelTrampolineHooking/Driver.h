#pragma once

#ifndef Driver_H
#define Driver_H

#include "Common.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject);
DRIVER_INITIALIZE DriverEntry;

#endif // Driver_H
