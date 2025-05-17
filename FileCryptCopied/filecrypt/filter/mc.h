/*++

Module Name:

    mc.h - Event Tracing

--*/

#ifndef __FC_MC_H__
#define __FC_MC_H__

#include <evntprov.h>
#include <ntdef.h>
#include "fc.h"

void
McGenControlCallbackV2 (
    undefined8 param_1,
    int param_2,
    undefined param_3,
    undefined8 param_4,
    undefined8 param_5,
    undefined8 param_6,
    long long param_7
    );

NTSTATUS
McGenEventRegister_EtwRegister(
    void
);

undefined8
McGenEventUnregister_EtwUnregister(
    void
    );

void
McGenEventWrite_EtwWriteTransfer (
    undefined8 param_1,
    PCEVENT_DESCRIPTOR EventDescriptor,
    undefined8 param_3,
    ULONG DataCount,
    PEVENT_DATA_DESCRIPTOR Data
    );

void
McTemplateK0d_EtwWriteTransfer (
    undefined8 param_1,
    PCEVENT_DESCRIPTOR EventDescriptor,
    undefined8 param_3,
    undefined4 param_4
    );

void
McTemplateK0pd_EtwWriteTransfer (
    undefined8 param_1,
    undefined8 param_2,
    undefined8 param_3,
    undefined8 param_4,
    undefined param_5
    );

void
McTemplateK0zd_EtwWriteTransfer (
    undefined8 param_1,
    undefined8 param_2,
    undefined8 param_3,
    wchar_t *param_4,
    undefined param_5
    );

void
McTemplateK0zzd_EtwWriteTransfer (
    undefined param_1,
    undefined param_2,
    undefined param_3,
    undefined param_4,
    wchar_t *param_5,
    undefined param_6
    );

#endif /* __FC_MC_H__ */