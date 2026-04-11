/* Ghidra decompilation of sqlservr BOOT functions */

/* ===== FUN_0020ba60 @ 0x20ba60 (runtime 0x10ba60) ===== */

void FUN_0020ba60(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7)

{
  undefined8 *puVar1;
  uint uVar2;
  char cVar3;
  undefined1 uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined4 *puVar9;
  ulong uVar10;
  long lVar11;
  undefined2 uVar12;
  long in_FS_OFFSET;
  undefined8 local_68;
  undefined8 uStack_60;
  ulong local_58;
  undefined8 uStack_50;
  uint local_44;
  undefined8 local_40;
  long local_38;
  
  local_38 = *(long *)(in_FS_OFFSET + 0x28);
  if (*(char *)(param_1 + 0x4b) == '\0') {
    *(undefined1 *)(param_1 + 0x4b) = 1;
    *param_1 = 0x90;
    *(undefined4 *)(param_1 + 1) = 0x38;
    param_1[2] = param_5;
    param_1[3] = param_6;
    param_1[4] = param_7;
    param_1[7] = param_3;
    param_1[8] = param_4;
    FUN_0020bcf0(param_1 + 0x12,param_2,DAT_00369f30);
    local_40 = 0;
    local_44 = 0;
    FUN_0029fd00(param_1 + 0x12,&local_40,&local_44);
    uVar8 = local_40;
    uVar7 = FUN_00297c90(param_2);
    cVar3 = FUN_002bdee0(uVar7);
    if (cVar3 == '\0') {
      param_1[9] = uVar8;
      uVar2 = local_44;
    }
    else {
      puVar1 = param_1 + 0x48;
      local_58 = 0;
      uStack_50 = 0;
      local_68 = 0;
      uStack_60 = 0;
      iVar5 = FUN_0029e430(puVar1,&local_68,0x20);
      if (iVar5 != 0) goto LAB_0020bc5d;
      local_68 = CONCAT44(local_68._4_4_,0x20);
      uStack_60 = uVar8;
      local_58 = (ulong)local_44;
      uVar8 = FUN_00297c80(param_2);
      uVar8 = FUN_002bdfc0(uVar8);
      uStack_50 = FUN_0029e2c0(puVar1,uVar8);
      uVar6 = FUN_0029df10(puVar1);
      local_68 = CONCAT44(uVar6,(undefined4)local_68);
      puVar9 = (undefined4 *)FUN_0029df00(puVar1);
      *puVar9 = (undefined4)local_68;
      puVar9[1] = local_68._4_4_;
      puVar9[2] = (undefined4)uStack_60;
      puVar9[3] = uStack_60._4_4_;
      *(ulong *)(puVar9 + 4) = local_58;
      *(undefined8 *)(puVar9 + 6) = uStack_50;
      param_1[9] = puVar9;
      uVar2 = local_68._4_4_;
    }
    param_1[10] = (ulong)uVar2;
    uVar8 = FUN_00297ca0(param_2);
    uVar8 = FUN_002bdfc0(uVar8);
    uVar10 = FUN_0029e2c0(param_1 + 0x48,uVar8);
    lVar11 = FUN_0029df00(param_1 + 0x48);
    param_1[6] = (uVar10 & 0xffffffff) + lVar11;
    uVar12 = (undefined2)(uVar10 >> 0x20);
    *(undefined2 *)(param_1 + 5) = uVar12;
    *(undefined2 *)((long)param_1 + 0x2a) = uVar12;
    uVar4 = FUN_0020d9c0();
    *(undefined1 *)(param_1 + 0xb) = uVar4;
    uVar8 = FUN_00296db0(param_2);
    param_1[0xc] = uVar8;
    uVar6 = FUN_00296dd0(param_2);
    *(undefined4 *)(param_1 + 0xd) = uVar6;
    if (*(long *)(in_FS_OFFSET + 0x28) == local_38) {
      return;
    }
                    /* WARNING: Subroutine does not return */
    FUN_00353500();
  }
  uVar8 = FUN_00353790(0x10);
                    /* try { // try from 0020bc38 to 0020bc46 has its CatchHandler @ 0020bc75 */
  FUN_00354360(uVar8,"The Guest OS initialization class cannot be loaded twice.");
  FUN_003537b0(uVar8,&std::runtime_error::typeinfo,PTR__runtime_error_00367550);
LAB_0020bc5d:
  puVar9 = (undefined4 *)FUN_00353860();
                    /* WARNING: Subroutine does not return */
  FUN_001c1100("offset == 0",*puVar9);
}



/* ===== FUN_0020bcf0 @ 0x20bcf0 (runtime 0x10bcf0) ===== */

void FUN_0020bcf0(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  char cVar1;
  undefined4 uVar2;
  long lVar3;
  undefined8 uVar4;
  
  FUN_0029e670(param_1,param_2,DAT_00369f28,param_3);
  FUN_0029fd70(param_1,0x40000);
  cVar1 = FUN_002896f0();
  if (cVar1 != '\0') {
    FUN_0029fd70(param_1,0x800000);
    FUN_0029fd70(param_1,0x20000);
  }
  cVar1 = FUN_00289720();
  if (cVar1 != '\0') {
    FUN_0029fd70(param_1,0x200000);
  }
  cVar1 = FUN_001bd240(param_2);
  if (cVar1 != '\0') {
    FUN_0029fd70(param_1,0x80000);
  }
  cVar1 = FUN_00205950(5,0xb);
  if (cVar1 == '\0') {
    FUN_0029fd70(param_1,0x100000);
  }
  uVar2 = FUN_00353eb0();
  lVar3 = FUN_0029fcf0(param_1);
  *(undefined4 *)(lVar3 + 0x14) = uVar2;
  FUN_0020be30(param_1,param_2);
  uVar4 = FUN_0020e390();
  lVar3 = FUN_0029fcf0(param_1);
  *(undefined8 *)(lVar3 + 0x170) = uVar4;
  FUN_0020bf60(param_1);
  FUN_0020c1c0(param_1);
  FUN_0020c330(param_1);
  FUN_0020c400(param_1);
  FUN_0020c4d0(param_1);
  FUN_0020c830(param_1,param_2);
  uVar4 = FUN_002b9600();
  uVar4 = FUN_002b9770(uVar4);
  lVar3 = FUN_0029fcf0(param_1);
  *(undefined8 *)(lVar3 + 0x160) = uVar4;
  return;
}



/* ===== FUN_002051e0 @ 0x2051e0 (runtime 0x1051e0) ===== */

undefined4 FUN_002051e0(long param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined1 *puVar4;
  long in_FS_OFFSET;
  byte local_70;
  undefined1 local_6f [15];
  undefined1 *local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined1 local_40 [8];
  undefined4 local_38;
  long local_28;
  
  local_28 = *(long *)(in_FS_OFFSET + 0x28);
  uVar3 = FUN_00297ca0(*(undefined8 *)(param_1 + 0x138));
  uVar3 = FUN_002bdfc0(uVar3);
  FUN_00353590(&local_70,uVar3);
  uVar3 = DAT_0036f2c0;
                    /* try { // try from 00205227 to 00205265 has its CatchHandler @ 002053b0 */
  iVar1 = FUN_002a19e0(DAT_0036f2c0);
  if (3 < iVar1) {
    puVar4 = local_60;
    if ((local_70 & 1) == 0) {
      puVar4 = local_6f;
    }
    FUN_002a1a20(4,uVar3,"pal.cpp",0x1e2,"Loading guest - %s",puVar4);
  }
                    /* try { // try from 00205266 to 0020527e has its CatchHandler @ 002053a9 */
  FUN_00251e30(local_40,&local_70,&local_48,&local_58,&local_50);
                    /* try { // try from 0020527f to 00205287 has its CatchHandler @ 002053b5 */
  uVar2 = FUN_0028e530(local_40);
  if ((char)uVar2 == '\0') {
                    /* try { // try from 002052a8 to 002052af has its CatchHandler @ 002053b5 */
    iVar1 = FUN_002a19e0(uVar3);
    if (3 < iVar1) {
      puVar4 = local_60;
      if ((local_70 & 1) == 0) {
        puVar4 = local_6f;
      }
                    /* try { // try from 00205344 to 0020536e has its CatchHandler @ 002053b5 */
      FUN_002a1a20(4,uVar3,"pal.cpp",0x20e,"Error loading guest (%s): %x",puVar4,local_38);
    }
  }
  else {
                    /* try { // try from 0020528f to 00205296 has its CatchHandler @ 002053ae */
    iVar1 = FUN_002a19e0(uVar3);
    if (3 < iVar1) {
      puVar4 = local_60;
      if ((local_70 & 1) == 0) {
        puVar4 = local_6f;
      }
                    /* try { // try from 002052c9 to 0020533a has its CatchHandler @ 002053ae */
      FUN_002a1a20(4,uVar3,"pal.cpp",0x1f6,
                   "Loaded guest %s\n  Entrypoint address is %p\n  Image base address is %p\n  Image length is %zu"
                   ,puVar4,local_50,local_48,local_58);
    }
    *(undefined4 *)(param_1 + 0x168) = 1;
    *(undefined8 *)(param_1 + 0x170) = local_50;
    *(undefined8 *)(param_1 + 0x178) = 0;
    *(undefined8 *)(param_1 + 0x180) = local_48;
    *(undefined8 *)(param_1 + 0x188) = local_58;
    FUN_0020fa40(&local_70);
  }
  FUN_0028e130(local_40);
  if ((local_70 & 1) != 0) {
    operator_delete(local_60);
  }
  if (*(long *)(in_FS_OFFSET + 0x28) != local_28) {
                    /* WARNING: Subroutine does not return */
    FUN_00353500();
  }
  return uVar2;
}



/* ===== FUN_002053e0 @ 0x2053e0 (runtime 0x1053e0) ===== */

void FUN_002053e0(long param_1)

{
  FUN_0020ba60(param_1 + 400,*(undefined8 *)(param_1 + 0x138),*(undefined8 *)(param_1 + 0x180),
               *(undefined8 *)(param_1 + 0x188),&DAT_00369ec8,&DAT_003b2138,0x18);
  return;
}



/* ===== FUN_00205430 @ 0x205430 (runtime 0x105430) ===== */

undefined4 FUN_00205430(long param_1)

{
  undefined8 uVar1;
  char cVar2;
  int iVar3;
  undefined8 uVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  
  if (*(int *)(param_1 + 8) != 2) {
    cVar2 = FUN_0029a110(*(undefined8 *)(param_1 + 0x138));
    if (cVar2 != '\0') {
      FUN_001d19d0();
    }
    cVar2 = FUN_001ae6e0(param_1);
    uVar6 = 0x65;
    if (cVar2 != '\0') {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 0x168);
      FUN_002065f0(param_1 + 0x18);
      FUN_001ae6e0(param_1);
      uVar6 = 2;
      if (*(long *)(param_1 + 0x170) != 0) {
        FUN_0027a630(0);
        uVar1 = *(undefined8 *)(param_1 + 0x170);
        uVar4 = FUN_0020bc90(param_1 + 400);
        iVar3 = FUN_00252e60(uVar1,uVar4,*(undefined8 *)(param_1 + 0x178),0,1,param_1 + 0x10);
        FUN_0027a630(1);
        uVar1 = DAT_0036f2c0;
        if (iVar3 < 0) {
          iVar3 = FUN_002a19e0(DAT_0036f2c0);
          uVar6 = 100;
          if (0 < iVar3) {
            FUN_002a1a20(1,uVar1,"pal.cpp",0x26b,"OS boot thread could not be started: %d",0);
          }
        }
      }
    }
    *(undefined4 *)(param_1 + 8) = uVar6;
    return uVar6;
  }
  puVar5 = (undefined4 *)FUN_00353860();
                    /* WARNING: Subroutine does not return */
  FUN_001c1100("PAL has already been booted",*puVar5);
}



/* ===== FUN_00252e60 @ 0x252e60 (runtime 0x152e60) ===== */

undefined8
FUN_00252e60(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 *param_4,
            char param_5,undefined8 *param_6)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  char cVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 *puVar8;
  code *pcVar9;
  long lVar10;
  undefined4 *puVar11;
  undefined1 *puVar12;
  undefined8 uVar13;
  long in_FS_OFFSET;
  byte local_b0;
  undefined1 local_af [15];
  undefined1 *local_a0;
  long local_98;
  long local_90;
  undefined1 local_88 [24];
  undefined1 local_70 [56];
  long local_38;
  
  local_38 = *(long *)(in_FS_OFFSET + 0x28);
  cVar5 = FUN_00280200();
  uVar13 = 0xc000000d;
  if ((cVar5 != '\0') &&
     ((param_4 == (undefined4 *)0x0 || (cVar5 = FUN_00280200(param_4), cVar5 != '\0')))) {
    uVar3 = DAT_0036f290;
    iVar6 = FUN_002a19e0(DAT_0036f290);
    if (3 < iVar6) {
      FUN_002a1a20(4,uVar3,"palcalls.cpp",0x131f,"ThreadCreate(%p, %p, %p)",param_1,param_2,param_3)
      ;
    }
    puVar8 = (undefined8 *)FUN_00354030(0xaa0,PTR_nothrow_003675a8);
    if (puVar8 == (undefined8 *)0x0) {
      puVar11 = (undefined4 *)FUN_00353860();
                    /* WARNING: Subroutine does not return */
      FUN_001c1100("t != nullptr",*puVar11);
    }
                    /* try { // try from 00252f2b to 00252f35 has its CatchHandler @ 00253306 */
    FUN_001fa870(puVar8);
    iVar6 = FUN_003541b0(&DAT_003b2198);
    if (iVar6 != 0) {
                    /* WARNING: Subroutine does not return */
      FUN_00354060();
    }
    DAT_003b21c0 = DAT_003b21c0 + 1;
    *(int *)(puVar8 + 0x12) = DAT_003b21c0;
    puVar4 = DAT_003b21c8;
    puVar8[0x13] = DAT_003b21c8;
    puVar8[0x14] = 0;
    if (puVar4 != (undefined8 *)0x0) {
      if (puVar4[0x14] != 0) {
        puVar11 = (undefined4 *)FUN_00353860();
                    /* WARNING: Subroutine does not return */
        FUN_001c1100("all_threads->tprev == nullptr",*puVar11);
      }
      puVar4[0x14] = puVar8;
    }
    DAT_003b21c8 = puVar8;
    iVar6 = FUN_003541c0(&DAT_003b2198);
    if (iVar6 != 0) {
                    /* WARNING: Subroutine does not return */
      FUN_00354060();
    }
    puVar8[0xb] = param_1;
    puVar8[0xc] = param_2;
    uVar13 = 0;
    if (param_5 == '\0') {
      uVar13 = param_2;
    }
    puVar8[0xd] = uVar13;
    puVar8[0xe] = param_3;
    if (*(int *)(DAT_0036f598 + 0xc) == 1) {
      pcVar9 = FUN_0025a520;
    }
    else {
      if (*(int *)(DAT_0036f598 + 0xc) != 2) {
        puVar11 = (undefined4 *)FUN_00353860();
                    /* WARNING: Subroutine does not return */
        FUN_001c1100("Unsupported PAL OS",*puVar11);
      }
      pcVar9 = FUN_0025a540;
    }
    puVar8[0x15] = pcVar9;
    if (param_4 != (undefined4 *)0x0) {
      uVar7 = param_4[1];
      uVar1 = param_4[2];
      uVar2 = param_4[3];
      *(undefined4 *)(puVar8 + 0xf) = *param_4;
      *(undefined4 *)((long)puVar8 + 0x7c) = uVar7;
      *(undefined4 *)(puVar8 + 0x10) = uVar1;
      *(undefined4 *)((long)puVar8 + 0x84) = uVar2;
    }
    lVar10 = FUN_001fa5f0(4);
    local_90 = lVar10;
    if (lVar10 == 0) {
      uVar13 = 0xc0000017;
                    /* try { // try from 0025313e to 00253145 has its CatchHandler @ 0025332e */
      FUN_002535c0(puVar8);
    }
    else {
      local_98 = lVar10;
                    /* try { // try from 0025303b to 00253042 has its CatchHandler @ 0025332e */
      FUN_002b6100(lVar10);
                    /* try { // try from 00253043 to 0025304a has its CatchHandler @ 002532f5 */
      FUN_002b60a0(lVar10);
                    /* try { // try from 0025304b to 00253052 has its CatchHandler @ 002532ed */
      FUN_002b6190(lVar10);
      *(undefined8 **)(lVar10 + 0x58) = puVar8;
                    /* try { // try from 00253058 to 00253086 has its CatchHandler @ 0025332e */
      uVar13 = FUN_002b6070(lVar10);
      *puVar8 = uVar13;
      if (param_6 != (undefined8 *)0x0) {
        uVar13 = FUN_002b6070(lVar10);
        *param_6 = uVar13;
        FUN_002b60d0(uVar13);
      }
                    /* try { // try from 00253091 to 00253095 has its CatchHandler @ 002532eb */
      uVar13 = FUN_001bbc30(*(undefined8 *)(DAT_0036f598 + 0x138));
      iVar6 = FUN_003553c0(local_70);
      if (iVar6 != 0) {
                    /* WARNING: Subroutine does not return */
        FUN_00354060();
      }
      iVar6 = FUN_003553d0(local_70,uVar13);
      if (iVar6 != 0) {
                    /* WARNING: Subroutine does not return */
        FUN_00354060();
      }
      uVar7 = FUN_00353f90(puVar8 + 4,local_70,FUN_00253350,puVar8);
                    /* try { // try from 002530d8 to 002530ee has its CatchHandler @ 002532e9 */
      FUN_0028e0f0(local_88,"palcalls.cpp",0x1374,uVar7);
                    /* try { // try from 002530ef to 00253110 has its CatchHandler @ 00253320 */
      cVar5 = FUN_0028e1f0(local_88);
      uVar13 = 0;
      if (cVar5 != '\0') {
        iVar6 = FUN_002a19e0(uVar3);
        if (3 < iVar6) {
                    /* try { // try from 00253116 to 00253125 has its CatchHandler @ 002532ad */
          FUN_0028e200(&local_b0,local_88);
          puVar12 = local_a0;
          if ((local_b0 & 1) == 0) {
            puVar12 = local_af;
          }
                    /* try { // try from 00253152 to 00253173 has its CatchHandler @ 0025328f */
          FUN_002a1a20(4,uVar3,"palcalls.cpp",0x137b,"pthread_create failed with %s",puVar12);
          if ((local_b0 & 1) != 0) {
            operator_delete(local_a0);
          }
        }
                    /* try { // try from 00253189 to 002531a8 has its CatchHandler @ 00253320 */
        FUN_002535c0(puVar8);
        *(undefined8 *)(lVar10 + 0x58) = 0;
        FUN_002b6100(lVar10);
                    /* try { // try from 002531a9 to 002531b0 has its CatchHandler @ 002532d0 */
        FUN_002b6190(lVar10);
                    /* try { // try from 002531b1 to 002531b8 has its CatchHandler @ 002532c8 */
        FUN_002b6190(lVar10);
        uVar13 = 0xc0000001;
        if (param_6 != (undefined8 *)0x0) {
                    /* try { // try from 002531d0 to 002531d7 has its CatchHandler @ 00253320 */
          FUN_002b6100(lVar10);
                    /* try { // try from 002531d8 to 002531df has its CatchHandler @ 002532b7 */
          FUN_002b6190(lVar10);
                    /* try { // try from 002531e0 to 002531e7 has its CatchHandler @ 002532af */
          FUN_002b6190(lVar10);
          *param_6 = 0;
        }
      }
      iVar6 = FUN_003553e0(local_70);
      if (iVar6 != 0) {
                    /* WARNING: Subroutine does not return */
        FUN_00354060();
      }
      FUN_0028e130(local_88);
                    /* try { // try from 0025320c to 00253213 has its CatchHandler @ 002532e1 */
      FUN_002b6190(lVar10);
    }
  }
  if (*(long *)(in_FS_OFFSET + 0x28) != local_38) {
                    /* WARNING: Subroutine does not return */
    FUN_00353500();
  }
  return uVar13;
}



/* ===== FUN_0025a520 @ 0x25a520 (runtime 0x15a520) ===== */

void FUN_0025a520(code *UNRECOVERED_JUMPTABLE,undefined8 param_2,undefined8 param_3,
                 undefined8 param_4)

{
                    /* WARNING: Could not recover jumptable at 0x0025a537. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(UNRECOVERED_JUMPTABLE,param_2,param_4,param_3);
  return;
}



/* ===== FUN_00279cd0 @ 0x279cd0 (runtime 0x179e28) ===== */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00279cd0(int param_1)

{
  DAT_00460900 = &DAT_0045f0e0;
  DAT_00460908 = &DAT_0045f1e1;
  _DAT_00460910 = &DAT_0045f2e2;
  _DAT_00460918 = &DAT_0045f3e3;
  _DAT_00460920 = &DAT_0045f4e4;
  _DAT_00460928 = &DAT_0045f5e5;
  _DAT_00460930 = &DAT_0045f6e6;
  _DAT_00460938 = &DAT_0045f7e7;
  _DAT_00460940 = &DAT_0045f8e8;
  _DAT_00460948 = &DAT_0045f9e9;
  _DAT_00460950 = &DAT_0045faea;
  _DAT_00460958 = &DAT_0045fbeb;
  _DAT_00460960 = &DAT_0045fcec;
  _DAT_00460968 = &DAT_0045fded;
  _DAT_00460970 = &DAT_0045feee;
  _DAT_00460978 = &DAT_0045ffef;
  _DAT_00460980 = &DAT_004600f0;
  _DAT_00460988 = &DAT_004601f1;
  _DAT_00460990 = &DAT_004602f2;
  _DAT_00460998 = &DAT_004603f3;
  _DAT_004609a0 = &DAT_004604f4;
  _DAT_004609a8 = &DAT_004605f5;
  _DAT_004609b0 = &DAT_004606f6;
  _DAT_004609b8 = &DAT_004607f7;
  FUN_00355c00(FUN_0027a980);
  FUN_00289700();
  DAT_004609c0 = (char)param_1;
  if (param_1 != 0) {
    FUN_00355c10(6,FUN_0027a580);
  }
  FUN_0027d7b0(4);
  FUN_0027d7b0(8);
  FUN_0027d7b0(0xb);
  FUN_0027d7b0(7);
  FUN_0027d7b0(5);
  FUN_0027d7b0(0xc);
  if (DAT_004609c0 != '\0') {
    FUN_00355c10(0x1f,FUN_0027a580);
    FUN_00355c10(0x18,FUN_0027a580);
    FUN_00355c10(0x19,FUN_0027a580);
    FUN_00355c10(0x10,FUN_0027a580);
    return;
  }
  return;
}



/* ===== FUN_0029fd00 @ 0x29fd00 (runtime 0x19fd00) ===== */

void FUN_0029fd00(long param_1,undefined8 *param_2,uint *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar2 = FUN_0029df10();
  if (399 < uVar2) {
    *(uint *)(param_1 + 0x24) = uVar2;
    uVar3 = FUN_0029df00(param_1);
    FUN_003536e0(uVar3,param_1 + 0x20,400);
    *param_2 = uVar3;
    *param_3 = uVar2;
    return;
  }
  puVar1 = (undefined4 *)FUN_00353860();
                    /* WARNING: Subroutine does not return */
  FUN_001c1100("size >= sizeof(WINDOWS_LIBOS_PARAMETERS)",*puVar1);
}



/* ===== FUN_0029fd70 @ 0x29fd70 (runtime 0x19fd70) ===== */

void FUN_0029fd70(long param_1,uint param_2)

{
  *(uint *)(param_1 + 0x30) = *(uint *)(param_1 + 0x30) | param_2;
  return;
}



/* ===== FUN_0029e670 @ 0x29e670 (runtime 0x19e670) ===== */

void FUN_0029e670(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  byte *pbVar1;
  long lVar2;
  undefined2 uVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  undefined8 *puVar6;
  long *plVar7;
  undefined4 *puVar8;
  ulong uVar9;
  byte *pbVar10;
  long lVar11;
  byte *pbVar12;
  
  if (*(char *)(param_1 + 0x18) != '\0') {
    puVar8 = (undefined4 *)FUN_00353860();
                    /* WARNING: Subroutine does not return */
    FUN_001c1100("The Guest OS parameters cannot be loaded twice.",*puVar8);
  }
  *(undefined1 *)(param_1 + 0x18) = 1;
  *(undefined4 *)(param_1 + 0x2c) = 0x38;
  *(undefined2 *)(param_1 + 0x6e) = 0x43;
  uVar4 = FUN_0029a5f0(param_2);
  *(undefined4 *)(param_1 + 0x19c) = uVar4;
  uVar4 = FUN_0029a510(param_2);
  *(undefined4 *)(param_1 + 0x3c) = uVar4;
  FUN_0029e9d0(param_1,param_2);
  *(undefined8 *)(param_1 + 0x48) = 0x25800000320;
  *(undefined4 *)(param_1 + 0x50) = 1;
  uVar5 = FUN_00296e10(param_2);
  *(undefined8 *)(param_1 + 0x188) = uVar5;
  *(undefined8 *)(param_1 + 0x58) = param_3;
  *(undefined8 *)(param_1 + 0x60) = param_4;
  FUN_0029eb00(param_1,param_2);
  FUN_0029eca0(param_1,param_2);
  FUN_0029eec0(param_1,param_2);
  uVar5 = FUN_002998a0(param_2);
  uVar5 = FUN_0029e350(param_1,uVar5);
  *(undefined8 *)(param_1 + 0xb0) = uVar5;
  uVar5 = FUN_00299890(param_2);
  uVar5 = FUN_0029e350(param_1,uVar5);
  *(undefined8 *)(param_1 + 0xa8) = uVar5;
  uVar5 = FUN_002998b0(param_2);
  uVar5 = FUN_0029e350(param_1,uVar5);
  *(undefined8 *)(param_1 + 0xb8) = uVar5;
  FUN_0029efd0(param_1,param_2);
  FUN_0029f210(param_1,param_2);
  FUN_0029f610(param_1,param_2);
  *(undefined8 *)(param_1 + 0xd8) = 0;
  puVar6 = (undefined8 *)FUN_00297d80(param_2);
  pbVar10 = (byte *)*puVar6;
  pbVar1 = (byte *)puVar6[1];
  if (pbVar10 != pbVar1) {
    do {
      if ((*pbVar10 & 1) == 0) {
        pbVar12 = pbVar10 + 1;
        uVar9 = (ulong)(*pbVar10 >> 1);
      }
      else {
        pbVar12 = *(byte **)(pbVar10 + 0x10);
        uVar9 = *(ulong *)(pbVar10 + 8);
      }
      FUN_0029df20(param_1,pbVar12,uVar9,param_1 + 0xd8);
      FUN_0029e150(param_1,&DAT_00146ec0,2,param_1 + 0xd8);
      pbVar10 = pbVar10 + 0x18;
    } while (pbVar10 != pbVar1);
  }
  FUN_0029e430(param_1,&DAT_00146ec2,2);
  pbVar10 = (byte *)FUN_00296d70(param_2);
  if ((*pbVar10 & 1) == 0) {
    if (*pbVar10 >> 1 == 0) goto LAB_0029e855;
  }
  else if (*(long *)(pbVar10 + 8) == 0) goto LAB_0029e855;
  uVar5 = FUN_00296d70(param_2);
  uVar5 = FUN_0029e2c0(param_1,uVar5);
  *(undefined8 *)(param_1 + 0xe8) = uVar5;
LAB_0029e855:
  uVar3 = FUN_00296e30(param_2);
  *(undefined2 *)(param_1 + 0x6c) = uVar3;
  FUN_0029f950(param_1,param_2);
  plVar7 = (long *)FUN_00297490(param_2);
  uVar9 = plVar7[1] - *plVar7;
  if (uVar9 == 0) {
    *(undefined8 *)(param_1 + 0x16c) = 0;
  }
  else {
    *(int *)(param_1 + 0x16c) = (int)(uVar9 >> 2);
    uVar4 = FUN_0029df10(param_1);
    *(undefined4 *)(param_1 + 0x170) = uVar4;
    puVar6 = (undefined8 *)FUN_00297490(param_2);
    FUN_0029e430(param_1,*puVar6,(uint)uVar9 & 0xfffffffc);
  }
  FUN_0029fae0(param_1,param_2);
  *(undefined8 *)(param_1 + 0x1a0) = 0;
  plVar7 = (long *)FUN_0029a730(param_2);
  lVar11 = *plVar7;
  lVar2 = plVar7[1];
  if (lVar11 != lVar2) {
    do {
      FUN_0029e100(param_1,lVar11,param_1 + 0x1a0);
      lVar11 = lVar11 + 0x18;
    } while (lVar11 != lVar2);
  }
  FUN_0029e430(param_1,&DAT_00146ec8,2);
  *(undefined8 *)(param_1 + 0x1a8) = 0;
  plVar7 = (long *)FUN_0029a5e0(param_2);
  lVar2 = plVar7[1];
  for (lVar11 = *plVar7; lVar11 != lVar2; lVar11 = lVar11 + 0x18) {
    FUN_0029e100(param_1,lVar11,param_1 + 0x1a8);
  }
  plVar7 = (long *)FUN_0029a5e0(param_2);
  if (*plVar7 != plVar7[1]) {
    FUN_0029e150(param_1,&DAT_00146eca,2,param_1 + 0x1a8);
    return;
  }
  return;
}



/* ===== FUN_00252aa0 @ 0x252aa0 (runtime 0x152aa0) ===== */

void FUN_00252aa0(undefined4 param_1,undefined8 param_2,undefined8 param_3)

{
  ulong uVar1;
  long *in_FS_OFFSET;
  
  uVar1 = FUN_00269540(param_1,param_3);
  if ((uVar1 & 1) == 0) {
    FUN_002899d0(param_1,param_2,param_3,*in_FS_OFFSET + -8);
  }
  return;
}



/* NOT FOUND: 0x20e498 */

/* ===== FUN_00214550 @ 0x214550 (runtime 0x114574) ===== */

char * FUN_00214550(undefined8 param_1,char *param_2,char *param_3,undefined8 param_4,long param_5)

{
  char cVar1;
  code *pcVar2;
  char *pcVar3;
  
  if (param_2 == param_3) {
    FUN_001e68d0();
    pcVar2 = (code *)swi(3);
    pcVar3 = (char *)(*pcVar2)();
    return pcVar3;
  }
  cVar1 = *param_2;
  if (cVar1 < 'b') {
    if (cVar1 < 'S') {
      if (cVar1 == '\0') {
        FUN_00353e60(param_4);
      }
      else {
        if (cVar1 != 'D') {
LAB_00214620:
          pcVar3 = (char *)FUN_00213a70(param_1,param_2);
          return pcVar3;
        }
        *(byte *)(param_5 + 0xa3) = *(byte *)(param_5 + 0xa3) | 8;
      }
    }
    else if (cVar1 == 'S') {
      *(byte *)(param_5 + 0xa3) = *(byte *)(param_5 + 0xa3) | 0x20;
    }
    else {
      if (cVar1 != 'W') goto LAB_00214620;
      *(byte *)(param_5 + 0xa3) = *(byte *)(param_5 + 0xa3) | 0xc;
      FUN_001ea990(param_5,0x5f);
    }
  }
  else if (cVar1 < 's') {
    if (cVar1 == 'b') {
      FUN_00353e60(param_4,8);
    }
    else {
      if (cVar1 != 'd') goto LAB_00214620;
      *(byte *)(param_5 + 0xa1) = *(byte *)(param_5 + 0xa1) | 8;
    }
  }
  else if (cVar1 == 's') {
    *(byte *)(param_5 + 0xa1) = *(byte *)(param_5 + 0xa1) | 0x20;
  }
  else {
    if (cVar1 != 'w') goto LAB_00214620;
    *(byte *)(param_5 + 0xa1) = *(byte *)(param_5 + 0xa1) | 0xc;
    FUN_001e7730(param_5,0x5f);
  }
  return param_2 + 1;
}



/* ===== FUN_00204680 @ 0x204680 (runtime 0x1046d8) ===== */

undefined8 FUN_00204680(long param_1,char param_2,undefined1 param_3)

{
  void *pvVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  undefined8 uVar7;
  undefined *puVar8;
  long in_FS_OFFSET;
  undefined1 local_b8 [8];
  undefined1 local_b0 [24];
  byte local_98;
  undefined7 uStack_97;
  byte bStack_90;
  undefined2 local_8f;
  undefined1 local_8d;
  undefined4 uStack_8c;
  undefined7 *local_88;
  undefined1 local_80 [8];
  undefined4 local_78;
  undefined1 local_68 [16];
  undefined1 local_58 [40];
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_0028e070(local_80);
  if (DAT_0036f618 == '\0') {
                    /* try { // try from 002046c2 to 002046ef has its CatchHandler @ 00204b91 */
    FUN_00354250(local_68);
    FUN_00354260(local_68,local_58);
    FUN_003536f0(param_1 + 0x3f8,local_58);
    FUN_00279cd0(param_3);
    uVar5 = *(undefined8 *)(param_1 + 0x138);
    if (param_2 != '\0') {
                    /* try { // try from 002046fc to 00204708 has its CatchHandler @ 00204b93 */
      FUN_0027a2f0();
    }
    cVar2 = FUN_001bd660(uVar5);
    if (cVar2 != '\0') {
      uVar3 = FUN_00353f90(local_b8,0,FUN_00204bb0,0);
                    /* try { // try from 00204724 to 0020473d has its CatchHandler @ 00204b3b */
      FUN_0028e0f0(&local_98,"pal.cpp",0xd8,uVar3);
                    /* try { // try from 0020473e to 0020474d has its CatchHandler @ 00204b39 */
      FUN_0028e560(local_80,&local_98);
      FUN_0028e130(&local_98);
                    /* try { // try from 0020475a to 00204762 has its CatchHandler @ 00204b37 */
      cVar2 = FUN_0028e1f0(local_80);
      if (cVar2 != '\0') {
        uVar5 = *(undefined8 *)PTR_stderr_003674f8;
                    /* try { // try from 00204ae6 to 00204af5 has its CatchHandler @ 00204b33 */
        FUN_0028e200(&local_98,local_80);
        if ((local_98 & 1) == 0) {
          local_88 = &uStack_97;
        }
        FUN_00353440(uVar5,"pthread_create failed with %s\n",local_88);
        FUN_003534a0(&local_98);
                    /* WARNING: Subroutine does not return */
        FUN_00354060();
      }
    }
    local_98 = 0x14;
    uStack_97 = 0x2e726567676f6c;
    bStack_90 = 0x69;
    local_8f = 0x696e;
    local_8d = 0;
                    /* try { // try from 00204793 to 0020479e has its CatchHandler @ 00204b66 */
    FUN_001f73d0(&local_98);
    if ((local_98 & 1) != 0) {
      operator_delete(local_88);
    }
                    /* try { // try from 002047b1 to 002047b5 has its CatchHandler @ 00204b93 */
    FUN_0021a7d0();
                    /* try { // try from 002047b6 to 002047c1 has its CatchHandler @ 00204b64 */
    FUN_0021d1c0(&local_98);
                    /* try { // try from 002047c2 to 002047d1 has its CatchHandler @ 00204b53 */
    FUN_0028e560(local_80,&local_98);
    FUN_0028e130(&local_98);
                    /* try { // try from 002047de to 00204826 has its CatchHandler @ 00204b93 */
    cVar2 = FUN_0028e1f0(local_80);
    if (cVar2 != '\0') {
      uVar5 = FUN_002a1dc0();
      iVar4 = FUN_002a19e0(uVar5);
      if (0 < iVar4) {
        uVar5 = FUN_002a1dc0();
        FUN_002a1a20(1,uVar5,"pal.cpp",0xf3,"Unable to initialize OpenSSL: error %x",local_78);
      }
      uVar5 = 0x66;
      goto LAB_00204ab2;
    }
    puVar8 = DAT_0036f610;
    if ((DAT_0036f600 & 1) == 0) {
      puVar8 = &DAT_0036f601;
    }
    lVar6 = FUN_003535c0(puVar8,&DAT_0013ab4f);
    if (lVar6 != 0) {
      FUN_00353770(&DAT_0013058c,4,1,lVar6);
      FUN_00353740(lVar6);
    }
                    /* try { // try from 0020487f to 002048b9 has its CatchHandler @ 00204b8f */
    FUN_0021a750();
    FUN_00252b70();
    FUN_002890a0();
    FUN_00353a90(1,4,0x400);
    FUN_00353a90(2,4,0x400);
    FUN_00354270(7,&local_98);
    local_98 = bStack_90;
    uStack_97 = (undefined7)
                (CONCAT44(uStack_8c,CONCAT13(local_8d,CONCAT21(local_8f,bStack_90))) >> 8);
    iVar4 = FUN_00354280(7,&local_98);
    uVar5 = DAT_0036f2c0;
                    /* try { // try from 002048f7 to 00204953 has its CatchHandler @ 00204b7d */
    if ((iVar4 != 0) && (iVar4 = FUN_002a19e0(DAT_0036f2c0), 1 < iVar4)) {
      FUN_002a1a20(2,uVar5,"pal.cpp",0x11d,&DAT_0012f402,
                   "Failed to increase the file descriptor limit.");
    }
    DAT_0036f618 = '\x01';
    FUN_002285a0(local_b0);
    FUN_0028e130(local_b0);
    FUN_00235a80();
    FUN_00244790();
  }
                    /* try { // try from 0020495b to 00204965 has its CatchHandler @ 00204b8d */
  FUN_001f1c50(local_58,0,param_1 + 0x410);
                    /* try { // try from 00204966 to 00204972 has its CatchHandler @ 00204b7f */
  FUN_0028e560(local_80,local_58);
  FUN_0028e130(local_58);
                    /* try { // try from 0020497c to 00204991 has its CatchHandler @ 00204b95 */
  cVar2 = FUN_0028e530(local_80);
  if (cVar2 == '\0') {
                    /* try { // try from 00204a6a to 00204aaa has its CatchHandler @ 00204b95 */
    uVar5 = FUN_002a1dc0();
    iVar4 = FUN_002a19e0(uVar5);
    uVar5 = 0x67;
    if (0 < iVar4) {
      uVar7 = FUN_002a1dc0();
      FUN_002a1a20(1,uVar7,"pal.cpp",0x145,"Unable to initialize async io: error %x",local_78);
    }
    goto LAB_00204ab2;
  }
  FUN_00279f10();
  *(undefined4 *)(param_1 + 8) = 1;
  pvVar1 = *(void **)(param_1 + 0x488);
  *(undefined8 *)(param_1 + 0x488) = 0;
  if (pvVar1 != (void *)0x0) {
    FUN_002b2100(pvVar1);
    operator_delete(pvVar1);
  }
  lVar6 = FUN_00354030(0x20,PTR_nothrow_003675a8);
  if (lVar6 != 0) {
                    /* try { // try from 002049da to 002049e1 has its CatchHandler @ 00204b3f */
    FUN_00200c90(lVar6);
  }
  pvVar1 = *(void **)(param_1 + 0x480);
  *(long *)(param_1 + 0x480) = lVar6;
  if (pvVar1 != (void *)0x0) {
    FUN_002b2100(pvVar1);
    operator_delete(pvVar1);
    lVar6 = *(long *)(param_1 + 0x480);
  }
  if (lVar6 == 0) {
LAB_00204a55:
    lVar6 = *(long *)(param_1 + 0x488);
  }
  else {
    lVar6 = FUN_00354030(0x20,PTR_nothrow_003675a8);
    if (lVar6 != 0) {
                    /* try { // try from 00204a2a to 00204a31 has its CatchHandler @ 00204b35 */
      FUN_001f1a40(lVar6);
    }
    pvVar1 = *(void **)(param_1 + 0x488);
    *(long *)(param_1 + 0x488) = lVar6;
    if (pvVar1 != (void *)0x0) {
      FUN_002b2100(pvVar1);
      operator_delete(pvVar1);
      goto LAB_00204a55;
    }
  }
  if (lVar6 == 0) {
    uVar5 = 0x67;
  }
  else {
    uVar5 = 0;
                    /* try { // try from 00204a63 to 00204a67 has its CatchHandler @ 00204b3d */
    FUN_00204da0();
  }
LAB_00204ab2:
  FUN_0028e130(local_80);
  if (*(long *)(in_FS_OFFSET + 0x28) != local_30) {
                    /* WARNING: Subroutine does not return */
    FUN_00353500();
  }
  return uVar5;
}



/* ===== FUN_00204680 @ 0x204680 (runtime 0x1046f9) ===== */

undefined8 FUN_00204680(long param_1,char param_2,undefined1 param_3)

{
  void *pvVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  undefined8 uVar7;
  undefined *puVar8;
  long in_FS_OFFSET;
  undefined1 local_b8 [8];
  undefined1 local_b0 [24];
  byte local_98;
  undefined7 uStack_97;
  byte bStack_90;
  undefined2 local_8f;
  undefined1 local_8d;
  undefined4 uStack_8c;
  undefined7 *local_88;
  undefined1 local_80 [8];
  undefined4 local_78;
  undefined1 local_68 [16];
  undefined1 local_58 [40];
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_0028e070(local_80);
  if (DAT_0036f618 == '\0') {
                    /* try { // try from 002046c2 to 002046ef has its CatchHandler @ 00204b91 */
    FUN_00354250(local_68);
    FUN_00354260(local_68,local_58);
    FUN_003536f0(param_1 + 0x3f8,local_58);
    FUN_00279cd0(param_3);
    uVar5 = *(undefined8 *)(param_1 + 0x138);
    if (param_2 != '\0') {
                    /* try { // try from 002046fc to 00204708 has its CatchHandler @ 00204b93 */
      FUN_0027a2f0();
    }
    cVar2 = FUN_001bd660(uVar5);
    if (cVar2 != '\0') {
      uVar3 = FUN_00353f90(local_b8,0,FUN_00204bb0,0);
                    /* try { // try from 00204724 to 0020473d has its CatchHandler @ 00204b3b */
      FUN_0028e0f0(&local_98,"pal.cpp",0xd8,uVar3);
                    /* try { // try from 0020473e to 0020474d has its CatchHandler @ 00204b39 */
      FUN_0028e560(local_80,&local_98);
      FUN_0028e130(&local_98);
                    /* try { // try from 0020475a to 00204762 has its CatchHandler @ 00204b37 */
      cVar2 = FUN_0028e1f0(local_80);
      if (cVar2 != '\0') {
        uVar5 = *(undefined8 *)PTR_stderr_003674f8;
                    /* try { // try from 00204ae6 to 00204af5 has its CatchHandler @ 00204b33 */
        FUN_0028e200(&local_98,local_80);
        if ((local_98 & 1) == 0) {
          local_88 = &uStack_97;
        }
        FUN_00353440(uVar5,"pthread_create failed with %s\n",local_88);
        FUN_003534a0(&local_98);
                    /* WARNING: Subroutine does not return */
        FUN_00354060();
      }
    }
    local_98 = 0x14;
    uStack_97 = 0x2e726567676f6c;
    bStack_90 = 0x69;
    local_8f = 0x696e;
    local_8d = 0;
                    /* try { // try from 00204793 to 0020479e has its CatchHandler @ 00204b66 */
    FUN_001f73d0(&local_98);
    if ((local_98 & 1) != 0) {
      operator_delete(local_88);
    }
                    /* try { // try from 002047b1 to 002047b5 has its CatchHandler @ 00204b93 */
    FUN_0021a7d0();
                    /* try { // try from 002047b6 to 002047c1 has its CatchHandler @ 00204b64 */
    FUN_0021d1c0(&local_98);
                    /* try { // try from 002047c2 to 002047d1 has its CatchHandler @ 00204b53 */
    FUN_0028e560(local_80,&local_98);
    FUN_0028e130(&local_98);
                    /* try { // try from 002047de to 00204826 has its CatchHandler @ 00204b93 */
    cVar2 = FUN_0028e1f0(local_80);
    if (cVar2 != '\0') {
      uVar5 = FUN_002a1dc0();
      iVar4 = FUN_002a19e0(uVar5);
      if (0 < iVar4) {
        uVar5 = FUN_002a1dc0();
        FUN_002a1a20(1,uVar5,"pal.cpp",0xf3,"Unable to initialize OpenSSL: error %x",local_78);
      }
      uVar5 = 0x66;
      goto LAB_00204ab2;
    }
    puVar8 = DAT_0036f610;
    if ((DAT_0036f600 & 1) == 0) {
      puVar8 = &DAT_0036f601;
    }
    lVar6 = FUN_003535c0(puVar8,&DAT_0013ab4f);
    if (lVar6 != 0) {
      FUN_00353770(&DAT_0013058c,4,1,lVar6);
      FUN_00353740(lVar6);
    }
                    /* try { // try from 0020487f to 002048b9 has its CatchHandler @ 00204b8f */
    FUN_0021a750();
    FUN_00252b70();
    FUN_002890a0();
    FUN_00353a90(1,4,0x400);
    FUN_00353a90(2,4,0x400);
    FUN_00354270(7,&local_98);
    local_98 = bStack_90;
    uStack_97 = (undefined7)
                (CONCAT44(uStack_8c,CONCAT13(local_8d,CONCAT21(local_8f,bStack_90))) >> 8);
    iVar4 = FUN_00354280(7,&local_98);
    uVar5 = DAT_0036f2c0;
                    /* try { // try from 002048f7 to 00204953 has its CatchHandler @ 00204b7d */
    if ((iVar4 != 0) && (iVar4 = FUN_002a19e0(DAT_0036f2c0), 1 < iVar4)) {
      FUN_002a1a20(2,uVar5,"pal.cpp",0x11d,&DAT_0012f402,
                   "Failed to increase the file descriptor limit.");
    }
    DAT_0036f618 = '\x01';
    FUN_002285a0(local_b0);
    FUN_0028e130(local_b0);
    FUN_00235a80();
    FUN_00244790();
  }
                    /* try { // try from 0020495b to 00204965 has its CatchHandler @ 00204b8d */
  FUN_001f1c50(local_58,0,param_1 + 0x410);
                    /* try { // try from 00204966 to 00204972 has its CatchHandler @ 00204b7f */
  FUN_0028e560(local_80,local_58);
  FUN_0028e130(local_58);
                    /* try { // try from 0020497c to 00204991 has its CatchHandler @ 00204b95 */
  cVar2 = FUN_0028e530(local_80);
  if (cVar2 == '\0') {
                    /* try { // try from 00204a6a to 00204aaa has its CatchHandler @ 00204b95 */
    uVar5 = FUN_002a1dc0();
    iVar4 = FUN_002a19e0(uVar5);
    uVar5 = 0x67;
    if (0 < iVar4) {
      uVar7 = FUN_002a1dc0();
      FUN_002a1a20(1,uVar7,"pal.cpp",0x145,"Unable to initialize async io: error %x",local_78);
    }
    goto LAB_00204ab2;
  }
  FUN_00279f10();
  *(undefined4 *)(param_1 + 8) = 1;
  pvVar1 = *(void **)(param_1 + 0x488);
  *(undefined8 *)(param_1 + 0x488) = 0;
  if (pvVar1 != (void *)0x0) {
    FUN_002b2100(pvVar1);
    operator_delete(pvVar1);
  }
  lVar6 = FUN_00354030(0x20,PTR_nothrow_003675a8);
  if (lVar6 != 0) {
                    /* try { // try from 002049da to 002049e1 has its CatchHandler @ 00204b3f */
    FUN_00200c90(lVar6);
  }
  pvVar1 = *(void **)(param_1 + 0x480);
  *(long *)(param_1 + 0x480) = lVar6;
  if (pvVar1 != (void *)0x0) {
    FUN_002b2100(pvVar1);
    operator_delete(pvVar1);
    lVar6 = *(long *)(param_1 + 0x480);
  }
  if (lVar6 == 0) {
LAB_00204a55:
    lVar6 = *(long *)(param_1 + 0x488);
  }
  else {
    lVar6 = FUN_00354030(0x20,PTR_nothrow_003675a8);
    if (lVar6 != 0) {
                    /* try { // try from 00204a2a to 00204a31 has its CatchHandler @ 00204b35 */
      FUN_001f1a40(lVar6);
    }
    pvVar1 = *(void **)(param_1 + 0x488);
    *(long *)(param_1 + 0x488) = lVar6;
    if (pvVar1 != (void *)0x0) {
      FUN_002b2100(pvVar1);
      operator_delete(pvVar1);
      goto LAB_00204a55;
    }
  }
  if (lVar6 == 0) {
    uVar5 = 0x67;
  }
  else {
    uVar5 = 0;
                    /* try { // try from 00204a63 to 00204a67 has its CatchHandler @ 00204b3d */
    FUN_00204da0();
  }
LAB_00204ab2:
  FUN_0028e130(local_80);
  if (*(long *)(in_FS_OFFSET + 0x28) != local_30) {
                    /* WARNING: Subroutine does not return */
    FUN_00353500();
  }
  return uVar5;
}



/* ===== FUN_00212d90 @ 0x212d90 (runtime 0x112e0c) ===== */

char * FUN_00212d90(long param_1,char *param_2,char *param_3)

{
  char cVar1;
  uint uVar2;
  long lVar3;
  undefined8 uVar4;
  int iVar5;
  undefined8 *puVar6;
  undefined *puVar7;
  long in_FS_OFFSET;
  undefined1 local_70 [24];
  undefined4 local_58;
  int local_54;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_2 != param_3) {
    iVar5 = (int)*param_2;
    if (iVar5 < 0x5c) {
      if (iVar5 == 0x24) {
        puVar6 = (undefined8 *)operator_new(0x18);
        uVar2 = *(uint *)(param_1 + 0x18);
        puVar7 = &DAT_00359130;
LAB_00212eaf:
        lVar3 = *(long *)(param_1 + 0x38);
        puVar6[1] = *(undefined8 *)(lVar3 + 8);
        *puVar6 = puVar7 + 0x10;
        *(bool *)(puVar6 + 2) = (uVar2 & 0x5f0) == 0x400;
        *(undefined8 **)(lVar3 + 8) = puVar6;
        *(undefined8 *)(param_1 + 0x38) = *(undefined8 *)(*(long *)(param_1 + 0x38) + 8);
        param_2 = param_2 + 1;
      }
      else if ((((iVar5 == 0x28) && (param_2 + 1 != param_3)) && (param_2[1] == '?')) &&
              (param_2 + 2 != param_3)) {
        cVar1 = param_2[2];
        if (cVar1 == '!') {
          FUN_001e5020(local_70);
          local_58 = *(undefined4 *)(param_1 + 0x18);
                    /* try { // try from 00212fce to 00212fdb has its CatchHandler @ 00213022 */
          param_2 = (char *)FUN_002122d0(local_70,param_2 + 3,param_3);
                    /* try { // try from 00212fe7 to 0021301c has its CatchHandler @ 00213026 */
          FUN_001e5080(param_1,local_70,1,*(undefined4 *)(param_1 + 0x1c));
          *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + local_54;
          if ((param_2 == param_3) || (*param_2 != ')')) {
            FUN_001e5130();
            goto LAB_0021301d;
          }
        }
        else {
          if (cVar1 != '=') goto LAB_00212edf;
          FUN_001e5020(local_70);
          local_58 = *(undefined4 *)(param_1 + 0x18);
                    /* try { // try from 00212e2c to 00212e39 has its CatchHandler @ 00213024 */
          param_2 = (char *)FUN_002122d0(local_70,param_2 + 3,param_3);
                    /* try { // try from 00212e45 to 00212e6a has its CatchHandler @ 00213028 */
          FUN_001e5080(param_1,local_70,0,*(undefined4 *)(param_1 + 0x1c));
          *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + local_54;
          if ((param_2 == param_3) || (*param_2 != ')')) {
            iVar5 = FUN_001e5130();
            goto LAB_00212e6b;
          }
        }
        param_2 = param_2 + 1;
        FUN_001e3680(local_70);
      }
    }
    else {
LAB_00212e6b:
      if (iVar5 == 0x5c) {
        if (param_2 + 1 != param_3) {
          cVar1 = param_2[1];
          if (cVar1 == 'B') {
            puVar6 = (undefined8 *)operator_new(0x30);
            puVar6[1] = *(undefined8 *)(*(long *)(param_1 + 0x38) + 8);
            *puVar6 = &PTR_FUN_00359170;
            FUN_00353800(puVar6 + 2,param_1);
            uVar4 = *(undefined8 *)(param_1 + 0x10);
            puVar6[3] = *(undefined8 *)(param_1 + 8);
            puVar6[4] = uVar4;
            *(undefined1 *)(puVar6 + 5) = 1;
          }
          else {
            if (cVar1 != 'b') goto LAB_00212edf;
            puVar6 = (undefined8 *)operator_new(0x30);
            puVar6[1] = *(undefined8 *)(*(long *)(param_1 + 0x38) + 8);
            *puVar6 = &PTR_FUN_00359170;
            FUN_00353800(puVar6 + 2,param_1);
            uVar4 = *(undefined8 *)(param_1 + 0x10);
            puVar6[3] = *(undefined8 *)(param_1 + 8);
            puVar6[4] = uVar4;
            *(undefined1 *)(puVar6 + 5) = 0;
          }
          *(undefined8 **)(*(long *)(param_1 + 0x38) + 8) = puVar6;
          *(undefined8 *)(param_1 + 0x38) = *(undefined8 *)(*(long *)(param_1 + 0x38) + 8);
          param_2 = param_2 + 2;
        }
      }
      else if (iVar5 == 0x5e) {
        puVar6 = (undefined8 *)operator_new(0x18);
        uVar2 = *(uint *)(param_1 + 0x18);
        puVar7 = &DAT_00359100;
        goto LAB_00212eaf;
      }
    }
  }
LAB_00212edf:
  if (*(long *)(in_FS_OFFSET + 0x28) == local_30) {
    return param_2;
  }
LAB_0021301d:
                    /* WARNING: Subroutine does not return */
  FUN_00353500();
}



/* ===== FUN_00213d10 @ 0x213d10 (runtime 0x113e0c) ===== */

/* WARNING: Type propagation algorithm not settling */

char * FUN_00213d10(long param_1,char *param_2,char *param_3,char *param_4)

{
  uint uVar1;
  bool bVar2;
  char cVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  ulong uVar7;
  char *pcVar8;
  ulong uVar9;
  long in_FS_OFFSET;
  bool bVar10;
  uint local_b8;
  undefined4 uStack_b4;
  undefined4 uStack_b0;
  undefined4 uStack_ac;
  void *local_a8;
  ulong local_98;
  ulong uStack_90;
  char *local_88;
  undefined8 local_78;
  undefined8 uStack_70;
  void *local_68;
  undefined8 local_58;
  ulong uStack_50;
  char *local_48;
  long local_38;
  
  local_38 = *(long *)(in_FS_OFFSET + 0x28);
  if ((param_2 != param_3) && (*param_2 != ']')) {
    local_58 = 0;
    uStack_50 = 0;
    local_48 = (char *)0x0;
    uVar9 = 0;
    if ((param_2 + 1 == param_3) || (*param_2 != '[')) {
LAB_00213dae:
      uVar1 = *(uint *)(param_1 + 0x18);
      uVar7 = uVar9 >> 1;
      if ((uVar9 & 1) != 0) {
        uVar7 = uStack_50;
      }
      if (uVar7 == 0) {
        if ((uVar1 & 0x1b0) == 0) {
          cVar3 = *param_2;
          if (cVar3 == '\\') {
            if ((uVar1 & 0x1f0) == 0) {
                    /* try { // try from 00213f42 to 00213f5a has its CatchHandler @ 00214122 */
              param_2 = (char *)FUN_00214550(param_1,param_2 + 1,param_3,&local_58,param_4);
            }
            else {
                    /* try { // try from 00213df7 to 00213e08 has its CatchHandler @ 00214173 */
              param_2 = (char *)FUN_00214640(param_1,param_2 + 1,param_3,&local_58);
            }
            goto joined_r0x00213e89;
          }
        }
        else {
          cVar3 = *param_2;
        }
                    /* try { // try from 00213e74 to 00213e7f has its CatchHandler @ 00214179 */
        FUN_00353e60(&local_58,(int)cVar3);
        param_2 = param_2 + 1;
      }
joined_r0x00213e89:
      if ((((param_2 == param_3) || (*param_2 == ']')) || (pcVar4 = param_2 + 1, pcVar4 == param_3))
         || ((*param_2 != '-' || (*pcVar4 == ']')))) {
        bVar10 = (local_58 & 1) == 0;
        uVar9 = uStack_50;
        if (bVar10) {
          uVar9 = local_58 >> 1 & 0x7f;
        }
        pcVar5 = param_2;
        pcVar4 = param_2;
        if (uVar9 != 0) {
          if (uVar9 == 1) {
            pcVar6 = local_48;
            if (bVar10) {
              pcVar6 = (char *)((long)&local_58 + 1);
            }
            FUN_001e7730(param_4,(int)*pcVar6);
          }
          else {
            pcVar6 = (char *)((long)&local_58 + 1);
            if ((local_58 & 1) != 0) {
              pcVar6 = local_48;
            }
            pcVar8 = (char *)((long)&local_58 + 1);
            if (!bVar10) {
              pcVar8 = local_48;
            }
                    /* try { // try from 00213fbb to 00213fcd has its CatchHandler @ 00214179 */
            FUN_001e9e30(param_4,(int)*pcVar6,(int)pcVar8[1]);
          }
        }
      }
      else {
        local_78 = 0;
        uStack_70 = 0;
        local_68 = (void *)0x0;
        pcVar5 = param_2 + 2;
        if (((pcVar5 == param_3) || (*pcVar4 != '[')) || (*pcVar5 != '.')) {
          if ((uVar1 & 0x1b0) == 0) {
            cVar3 = *pcVar4;
            if (cVar3 == '\\') {
              if ((uVar1 & 0x1f0) == 0) {
                    /* try { // try from 0021402b to 00214046 has its CatchHandler @ 00214102 */
                pcVar5 = (char *)FUN_00214550(param_1,pcVar5,param_3,&local_78,param_4);
              }
              else {
                    /* try { // try from 00213f24 to 00213f35 has its CatchHandler @ 00214106 */
                pcVar5 = (char *)FUN_00214640(param_1,pcVar5,param_3,&local_78);
              }
              goto LAB_0021404a;
            }
          }
          else {
            cVar3 = *pcVar4;
          }
                    /* try { // try from 00214016 to 00214021 has its CatchHandler @ 00214108 */
          FUN_00353e60(&local_78,(int)cVar3);
        }
        else {
                    /* try { // try from 00213ee2 to 00213ef3 has its CatchHandler @ 00214104 */
          pcVar5 = (char *)FUN_00214460(param_1,param_2 + 3,param_3,&local_78);
        }
LAB_0021404a:
        local_88 = local_48;
        local_98 = local_58;
        uStack_90 = uStack_50;
        local_58 = 0;
        uStack_50 = 0;
        local_48 = (char *)0x0;
        local_b8 = (uint)local_78;
        uStack_b4 = local_78._4_4_;
        uStack_b0 = (undefined4)uStack_70;
        uStack_ac = uStack_70._4_4_;
        local_a8 = local_68;
        local_78 = 0;
        uStack_70 = 0;
        local_68 = (void *)0x0;
                    /* try { // try from 0021408e to 002140a3 has its CatchHandler @ 00214124 */
        FUN_001e9990(param_4,&local_98,&local_b8);
        if ((local_b8 & 1) != 0) {
          operator_delete(local_a8);
        }
        if ((local_98 & 1) != 0) {
          operator_delete(local_88);
        }
        pcVar4 = param_4;
        if ((local_78 & 1) != 0) {
          operator_delete(local_68);
        }
      }
      bVar2 = true;
      bVar10 = true;
      param_2 = pcVar5;
    }
    else {
      cVar3 = param_2[1];
      if (cVar3 == '.') {
                    /* try { // try from 00213e19 to 00213e2a has its CatchHandler @ 00214175 */
        param_2 = (char *)FUN_00214460(param_1,param_2 + 2,param_3,&local_58);
        uVar9 = local_58 & 0xff;
        goto LAB_00213dae;
      }
      if (cVar3 == ':') {
                    /* try { // try from 00213e3f to 00213e49 has its CatchHandler @ 00214177 */
        pcVar4 = (char *)FUN_002143d0(param_1,param_2 + 2,param_3);
      }
      else {
        if (cVar3 != '=') {
          uVar9 = 0;
          goto LAB_00213dae;
        }
                    /* try { // try from 00213d97 to 00213da1 has its CatchHandler @ 00214177 */
        pcVar4 = (char *)FUN_002141a0(param_1,param_2 + 2,param_3);
      }
      bVar2 = false;
      bVar10 = false;
    }
    if ((local_58 & 1) != 0) {
      operator_delete(local_48);
      bVar10 = bVar2;
    }
    if (!bVar10) goto LAB_00213feb;
  }
  pcVar4 = param_2;
LAB_00213feb:
  if (*(long *)(in_FS_OFFSET + 0x28) != local_38) {
                    /* WARNING: Subroutine does not return */
    FUN_00353500();
  }
  return pcVar4;
}



