/** @file
  LZMA ("LZMA_ALONE" / UEFI-LZMA) decompression for the boot payload.

  Why this exists: the prelinked macOS kernel is a kernel collection whose image is as large as the
  original kernelcache (here 132.8 MiB), while vendor_boot_a is 96 MiB. The payload therefore carries
  `kernel.macho.lzma` instead of `kernel.macho`, and the loader decompresses it before ParseKernel().

  Container: the same one EDK2 uses for compressed firmware volumes — 5 property bytes, an 8-byte
  little-endian uncompressed size, then the raw LZMA stream. That is byte-for-byte what
  `lzma.compress(data, format=lzma.FORMAT_ALONE)` writes, so the host side needs no EDK2 tooling.

  Decoder: Igor Pavlov's LZMA SDK (public domain), vendored under Lzma/ from MdeModulePkg's
  LzmaCustomDecompressLib. It is vendored rather than linked so this driver needs no
  ExtractGuidedSectionLib, no guided-section constructor and no DSC library-class override.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "DarwinBootLzma.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

#include "7zTypes.h"
#include "LzmaDec.h"

//
// The two entry points below follow MdeModulePkg/Library/LzmaCustomDecompressLib/LzmaDecompress.c:
// same header contract, same LZMA_FINISH_END call, same fixed-size scratch buffer for the probability
// model, and the destination buffer doubles as the dictionary.
//
#define DARWINBOOT_LZMA_SCRATCH_SIZE  SIZE_64KB
#define DARWINBOOT_LZMA_HEADER_SIZE   (LZMA_PROPS_SIZE + 8)

STATIC_ASSERT (DARWINBOOT_LZMA_PROPS_SIZE == LZMA_PROPS_SIZE, "the payload header contract and the decoder must agree");

typedef struct {
  ISzAlloc    Functions;
  VOID        *Buffer;
  UINTN       BufferSize;
} DARWINBOOT_LZMA_ALLOC;

STATIC
VOID *
EFIAPI
LzmaSzAlloc (
  CONST ISzAlloc  *Allocator,
  size_t          Size
  )
{
  DARWINBOOT_LZMA_ALLOC  *Private;
  VOID                   *Address;

  Private = (DARWINBOOT_LZMA_ALLOC *)Allocator;
  if (Private->BufferSize < Size) {
    return NULL;
  }

  Address         = Private->Buffer;
  Private->Buffer = (VOID *)((UINT8 *)Address + Size);
  Private->BufferSize -= Size;
  return Address;
}

STATIC
VOID
EFIAPI
LzmaSzFree (
  CONST ISzAlloc  *Allocator,
  VOID            *Address
  )
{
  //
  // Every allocation comes out of the one scratch buffer the caller owns.
  //
  (VOID)Allocator;
  (VOID)Address;
}

/**
  Read the uncompressed size out of a DarwinBoot LZMA header.

  @param[in]  Source           Compressed data, header included.
  @param[in]  SourceSize       Size of Source.
  @param[out] DestinationSize  Recorded uncompressed size.

  @retval EFI_SUCCESS            The header is complete and the size fits a UINTN.
  @retval EFI_INVALID_PARAMETER  Source is shorter than the header.
  @retval EFI_BAD_BUFFER_SIZE    The recorded size does not fit a UINTN on this architecture.
**/
EFI_STATUS
DarwinBootLzmaGetInfo (
  IN  CONST VOID  *Source,
  IN  UINTN       SourceSize,
  OUT UINT64      *DestinationSize
  )
{
  CONST UINT8  *Header;
  UINT64       Decoded;
  INTN         Index;

  if ((Source == NULL) || (DestinationSize == NULL) || (SourceSize < DARWINBOOT_LZMA_HEADER_SIZE)) {
    return EFI_INVALID_PARAMETER;
  }

  Header  = (CONST UINT8 *)Source;
  Decoded = 0;
  for (Index = LZMA_PROPS_SIZE + 7; Index >= LZMA_PROPS_SIZE; Index--) {
    Decoded = LShiftU64 (Decoded, 8) + Header[Index];
  }

  if (Decoded > MAX_UINTN) {
    return EFI_BAD_BUFFER_SIZE;
  }

  *DestinationSize = Decoded;
  return EFI_SUCCESS;
}

/**
  Decompress a DarwinBoot LZMA buffer.

  @param[in]  Source           Compressed data, header included.
  @param[in]  SourceSize       Size of Source.
  @param[in]  Destination      Buffer that receives the uncompressed bytes; also the dictionary.
  @param[in]  DestinationSize  Size of Destination, exactly the size the header records.

  @retval EFI_SUCCESS            Destination holds the uncompressed image.
  @retval EFI_INVALID_PARAMETER  The stream is corrupt or the sizes disagree.
  @retval EFI_OUT_OF_RESOURCES   The scratch allocation failed.
**/
EFI_STATUS
DarwinBootLzmaDecompress (
  IN CONST VOID  *Source,
  IN UINTN       SourceSize,
  IN VOID        *Destination,
  IN UINTN       DestinationSize
  )
{
  DARWINBOOT_LZMA_ALLOC  Allocator;
  SRes                   Result;
  ELzmaStatus            Status;
  SizeT                  DecodedSize;
  SizeT                  EncodedSize;
  UINT64                 Recorded;
  EFI_STATUS             Status2;
  VOID                   *Scratch;

  if ((Source == NULL) || (Destination == NULL) || (DestinationSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Status2 = DarwinBootLzmaGetInfo (Source, SourceSize, &Recorded);
  if (EFI_ERROR (Status2)) {
    return Status2;
  }

  if (Recorded != DestinationSize) {
    return EFI_INVALID_PARAMETER;
  }

  Scratch = AllocatePool (DARWINBOOT_LZMA_SCRATCH_SIZE);
  if (Scratch == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Allocator.Functions.Alloc = LzmaSzAlloc;
  Allocator.Functions.Free  = LzmaSzFree;
  Allocator.Buffer          = Scratch;
  Allocator.BufferSize      = DARWINBOOT_LZMA_SCRATCH_SIZE;

  Status          = LZMA_STATUS_NOT_SPECIFIED;
  DecodedSize     = (SizeT)DestinationSize;
  EncodedSize     = (SizeT)(SourceSize - DARWINBOOT_LZMA_HEADER_SIZE);
  Result          = LzmaDecode (
                      Destination,
                      &DecodedSize,
                      (Byte *)((UINT8 *)Source + DARWINBOOT_LZMA_HEADER_SIZE),
                      &EncodedSize,
                      (CONST Byte *)Source,
                      LZMA_PROPS_SIZE,
                      LZMA_FINISH_END,
                      &Status,
                      &Allocator.Functions
                      );

  FreePool (Scratch);

  if ((Result != SZ_OK) || (DecodedSize != DestinationSize)) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}
