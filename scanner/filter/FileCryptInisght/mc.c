#include "mc.h"


void
McGenControlCallbackV2 (
  undefined8 param_1,
  int param_2,
  undefined param_3,
  undefined8 param_4,
  undefined8 param_5,
  undefined8 param_6,
  longlong param_7
  )
{
  byte *pbVar1;
  uint *puVar2;
  byte bVar3;
  ulonglong uVar4;
  bool bVar5;
  bool bVar6;
  uint uVar7;
  ulonglong uVar8;
  uint uVar9;
  
  uVar8 = 0;
  if (param_7 != 0) {
    bVar6 = false;
    if (param_2 == 0) {
      *(undefined4 *)(param_7 + 0x24) = 0;
      *(undefined *)(param_7 + 0x28) = 0;
      *(undefined8 *)(param_7 + 0x10) = 0;
      *(undefined8 *)(param_7 + 0x18) = 0;
      if (*(ushort *)(param_7 + 0x2a) != 0) {
        memset(*(void **)(param_7 + 0x30),0,(longlong)((int)(*(ushort *)(param_7 + 0x2a) - 1) / 0x20 + 1) << 2);
      }
    }
    else if (param_2 == 1) {
      *(undefined *)(param_7 + 0x28) = param_3;
      *(undefined8 *)(param_7 + 0x18) = param_5;
      *(undefined8 *)(param_7 + 0x10) = param_4;
      *(undefined4 *)(param_7 + 0x24) = 1;
      if (*(short *)(param_7 + 0x2a) != 0) {
        do {
          bVar3 = *(byte *)(param_7 + 0x28);
          uVar4 = *(ulonglong *)(*(longlong *)(param_7 + 0x38) + uVar8 * 8);
          pbVar1 = (byte *)(uVar8 + *(longlong *)(param_7 + 0x40));
          bVar5 = bVar6;
          if (((*pbVar1 < bVar3 || *pbVar1 == bVar3) || (bVar3 == 0)) &&
             ((uVar4 == 0 ||
              (((*(ulonglong *)(param_7 + 0x10) & uVar4) != 0 &&
               ((*(ulonglong *)(param_7 + 0x18) & uVar4) == *(ulonglong *)(param_7 + 0x18))))))) {
            bVar5 = true;
          }
          uVar7 = 1 << ((byte)uVar8 & 0x1f);
          puVar2 = (uint *)(*(longlong *)(param_7 + 0x30) + (uVar8 >> 5) * 4);
          uVar9 = *puVar2;
          if (bVar5) {
            uVar7 = uVar7 | uVar9;
          }
          else {
            uVar7 = ~uVar7 & uVar9;
          }
          *puVar2 = uVar7;
          uVar9 = (int)uVar8 + 1;
          uVar8 = (ulonglong)uVar9;
        } while (uVar9 < *(ushort *)(param_7 + 0x2a));
      }
    }
  }
}


NTSTATUS McGenEventRegister_EtwRegister(void)

{
  if (FileCryptGuid_Context != NULL) {
    return STATUS_SUCCESS;
  }
  
  return EtwRegister(
    &FileCryptGuid,
    McGenControlCallbackV2,
    &FileCryptGuid_Context,
    &FileCryptGuid_Context
    );
}

