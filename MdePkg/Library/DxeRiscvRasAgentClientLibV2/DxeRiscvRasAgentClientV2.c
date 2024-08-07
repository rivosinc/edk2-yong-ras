/** @file
  This module provides communication with RAS Agent over RPMI/MPXY

  Copyright (c) 2024, Ventana Micro Systems, Inc.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Uefi.h>

#include <IndustryStandard/Acpi.h>

#include <Protocol/AcpiTable.h>

#include <Guid/EventGroup.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/FdtClient.h>
#include <Protocol/MmCommunication2.h>

#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/SafeIntLib.h>
#include <Library/BaseRiscVSbiLib.h>

#include <Library/DxeRiscvMpxy.h>
#include <Library/DxeRiscvRasAgentClient.h>

#define MAX_SOURCES                   512
#define MAX_DESC_SIZE                 1024

///
/// Size of SMM communicate header, without including the payload.
///
#define MM_COMMUNICATE_HEADER_SIZE  (OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data))

/* RAS Agent Services on MPXY/RPMI */
#define RAS_GET_NUM_ERR_SRCS            0x1
#define RAS_GET_ERR_SRCS_ID_LIST        0x2
#define RAS_GET_ERR_SRC_DESC            0x3

#define __packed32 __attribute__((packed,aligned(__alignof__(UINT32))))
EFI_MM_COMMUNICATION2_PROTOCOL  *mMmCommunication2                   = NULL;

typedef struct __packed32 {
  UINT32 status;
  UINT32 flags;
  UINT32 remaining;
  UINT32 returned;
  UINT32 func_id;
} RasRpmiRespHeader;

typedef struct __packed32 {
  RasRpmiRespHeader RespHdr;
  UINT32 ErrSourceList[MAX_SOURCES];
} ErrorSourceListResp;

typedef struct __packed32 {
  RasRpmiRespHeader RspHdr;
  UINT8 desc[MAX_DESC_SIZE];
} ErrDescResp;

static ErrorSourceListResp gErrorSourceListResp;
static ErrDescResp gErrDescResp;
UINT32 gMpxyChannelId = 0;


EFI_STATUS
EFIAPI
RacInit (
  VOID
  )
{
  EFI_STATUS Status;
  Status = gBS->LocateProtocol (&gEfiMmCommunication2ProtocolGuid, NULL, (VOID **)&mMmCommunication2);
  ASSERT_EFI_ERROR (Status);

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RacGetNumberErrorSources(
  UINT32 *NumErrorSources
  )
{
  EFI_MM_COMMUNICATE_HEADER        *SmmCommunicateHeader;
  UINTN                       CommBufferSize;

  struct __packed32 _NumErrSrc {
    RasRpmiRespHeader RespHdr;
    UINT32 NumErrorSources;
  } RasMsgBuf;

  EFI_STATUS Status;
  RasRpmiRespHeader *RespHdr = &RasMsgBuf.RespHdr;
  
  ZeroMem (&RasMsgBuf, sizeof(RasMsgBuf));
  RespHdr->func_id = RAS_GET_NUM_ERR_SRCS;

  // Initialize the RAS agent client library.
  Status = RacInit ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  CommBufferSize =
    MM_COMMUNICATE_HEADER_SIZE + sizeof(RasMsgBuf);
  SmmCommunicateHeader = AllocateZeroPool (CommBufferSize);
  CopyGuid (&SmmCommunicateHeader->HeaderGuid, &gMmHestGetErrorSourceInfoGuid);
  CopyMem(SmmCommunicateHeader->Data, (const void*) &RasMsgBuf, sizeof(RasMsgBuf));
  SmmCommunicateHeader->MessageLength = sizeof(RasMsgBuf);


  Status = mMmCommunication2->Communicate (mMmCommunication2, SmmCommunicateHeader, SmmCommunicateHeader, &CommBufferSize );

  if (Status != EFI_SUCCESS) {
    return Status;
  }

  if (RespHdr->status != 0) {
    return EFI_DEVICE_ERROR;
  }

  CopyMem(&RasMsgBuf, (const void*)SmmCommunicateHeader->Data, sizeof(RasMsgBuf));

  *NumErrorSources = RasMsgBuf.NumErrorSources;
  FreePool(SmmCommunicateHeader);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RacGetErrorSourceIDList(
  OUT UINT32 **ErrorSourceList,
  OUT UINT32 *NumSources
  )
{
  UINT32 *RespData = &gErrorSourceListResp.ErrSourceList[0];
  RasRpmiRespHeader *RespHdr = &gErrorSourceListResp.RespHdr;
  EFI_STATUS Status;
  UINTN RespLen = sizeof(gErrorSourceListResp);
  EFI_MM_COMMUNICATE_HEADER        *SmmCommunicateHeader;
  UINTN                       CommBufferSize;

  ZeroMem(&gErrorSourceListResp, sizeof(gErrorSourceListResp));

  if (!ErrorSourceList)
    return EFI_INVALID_PARAMETER;

  CommBufferSize =
    MM_COMMUNICATE_HEADER_SIZE + RespLen;
  SmmCommunicateHeader = AllocateZeroPool (CommBufferSize);
  CopyGuid (&SmmCommunicateHeader->HeaderGuid, &gMmHestGetErrorSourceInfoGuid);
  gErrorSourceListResp.RespHdr.func_id = RAS_GET_ERR_SRCS_ID_LIST;
  CopyMem(SmmCommunicateHeader->Data, (const void*) &gErrorSourceListResp, RespLen);
  SmmCommunicateHeader->MessageLength = sizeof(ErrorSourceListResp);


  Status = mMmCommunication2->Communicate (mMmCommunication2, SmmCommunicateHeader, SmmCommunicateHeader, &CommBufferSize );

  if (Status != EFI_SUCCESS) {
    return Status;
  }

  if (RespHdr->status != 0) {
    return EFI_DEVICE_ERROR;
  }

  CopyMem(&gErrorSourceListResp, (const void*)SmmCommunicateHeader->Data, RespLen);

  //RespData = gErrorSourceListResp.ErrSourceList[0];
  *NumSources = RespHdr->returned;
  *ErrorSourceList = RespData;

  FreePool(SmmCommunicateHeader);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RacGetErrorSourceDescriptor(
  IN UINT32 SourceID,
  OUT UINTN *DescriptorType,
  OUT VOID **ErrorDescriptor,
  OUT UINT32 *ErrorDescriptorSize
  )
{
  UINTN RespLen = sizeof(gErrDescResp);
  EFI_STATUS Status;
  RasRpmiRespHeader *RspHdr = &gErrDescResp.RspHdr;
  UINT8 *desc = &gErrDescResp.desc[0];
  EFI_MM_COMMUNICATE_HEADER        *SmmCommunicateHeader;
  UINTN                       CommBufferSize;

  ZeroMem(&gErrDescResp, sizeof(gErrDescResp));

  *desc = SourceID;
  DEBUG ((DEBUG_INFO, "%a: Dhaval \n",__func__));

  CommBufferSize =
    MM_COMMUNICATE_HEADER_SIZE + RespLen;
  SmmCommunicateHeader = AllocateZeroPool (CommBufferSize);
  CopyGuid (&SmmCommunicateHeader->HeaderGuid, &gMmHestGetErrorSourceInfoGuid);
  gErrDescResp.RspHdr.func_id = RAS_GET_ERR_SRC_DESC;
  CopyMem(SmmCommunicateHeader->Data, (const void*) &gErrDescResp, RespLen);
  SmmCommunicateHeader->MessageLength = sizeof(ErrDescResp);

  Status = mMmCommunication2->Communicate (mMmCommunication2, SmmCommunicateHeader, SmmCommunicateHeader, &CommBufferSize );

  CopyMem(&gErrDescResp, (const void*)SmmCommunicateHeader->Data, RespLen);
  if (Status != EFI_SUCCESS)
    return Status;

  if (RspHdr->status != 0)
    return EFI_DEVICE_ERROR;

  if (RspHdr->remaining != 0)
    return EFI_DEVICE_ERROR;

  *DescriptorType = RspHdr->flags & ERROR_DESCRIPTOR_TYPE_MASK;

  ASSERT(*DescriptorType < MAX_ERROR_DESCRIPTOR_TYPES);

  *ErrorDescriptor = (VOID *)desc;
  *ErrorDescriptorSize = RspHdr->returned;

  FreePool(SmmCommunicateHeader);
  return EFI_SUCCESS;
}
