/** @file
  LZMA decompression for the boot payload.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

//
// Property bytes that precede the 8-byte size and the stream; the same constant EDK2 uses for
// compressed firmware volumes, and the same layout Python writes with format=lzma.FORMAT_ALONE.
//
#define DARWINBOOT_LZMA_PROPS_SIZE  5

/**
  Read the uncompressed size out of a LZMA header.

  @param[in]  Source           Compressed data, header included.
  @param[in]  SourceSize       Size of Source.
  @param[out] DestinationSize  Recorded uncompressed size.

  @retval EFI_SUCCESS            The header is complete.
  @retval EFI_INVALID_PARAMETER  Source is shorter than the header.
  @retval EFI_BAD_BUFFER_SIZE    The recorded size does not fit a UINTN.
**/
EFI_STATUS
DarwinBootLzmaGetInfo (
  IN  CONST VOID  *Source,
  IN  UINTN       SourceSize,
  OUT UINT64      *DestinationSize
  );

/**
  Decompress a LZMA buffer into a caller-provided destination.

  @param[in] Source           Compressed data, header included.
  @param[in] SourceSize       Size of Source.
  @param[in] Destination      Buffer that receives the bytes; also serves as the dictionary.
  @param[in] DestinationSize  Its size, exactly the size the header records.

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
  );
