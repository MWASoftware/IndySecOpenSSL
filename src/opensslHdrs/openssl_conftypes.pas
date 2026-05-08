{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License"), and as
    a derived work of the OpenSSL Project (see below for the original licence text).

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.
}

{$include openssl_defines.inc}

unit openssl_conftypes;

{
  Generated from OpenSSL 3.0.20 Header File conftypes.h - Fri  8 May 11:30:51 BST 2026
  With Legacy Support Option
}

interface

uses OpenSSLAPI,openssl_types,openssl_conf;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CONFTYPES_H}
  {$define OPENSSL_CONFTYPES_H}
  {$ifndef  OPENSSL_CONF_H}
  {$endif}

type
  {Auto-generated forward references}
  PTFuncType000 = ^TFuncType000;
  PPTFuncType000 = ^PTFuncType000;
  PTFuncType001 = ^TFuncType001;
  PPTFuncType001 = ^PTFuncType001;
  PTFuncType002 = ^TFuncType002;
  PPTFuncType002 = ^PTFuncType002;
  PTFuncType003 = ^TFuncType003;
  PPTFuncType003 = ^PTFuncType003;
  PTFuncType004 = ^TFuncType004;
  PPTFuncType004 = ^PTFuncType004;
  PTFuncType005 = ^TFuncType005;
  PPTFuncType005 = ^PTFuncType005;
  PTFuncType006 = ^TFuncType006;
  PPTFuncType006 = ^PTFuncType006;
  PTFuncType007 = ^TFuncType007;
  PPTFuncType007 = ^PTFuncType007;
  PTFuncType008 = ^TFuncType008;
  PPTFuncType008 = ^PTFuncType008;
  Pconf_method_st = ^Tconf_method_st;
  PPconf_method_st = ^Pconf_method_st;
  Pconf_st = ^Tconf_st;
  PPconf_st = ^Pconf_st;
  {end of auto-generated forward references}

  
  {* The contents of this file are deprecated and will be made opaque
  }
  TFuncType000 = function(meth: PCONF_METHOD): PCONF; cdecl;
  TFuncType001 = function(conf: PCONF): TOpenSSL_C_INT; cdecl;
  TFuncType002 = function(conf: PCONF): TOpenSSL_C_INT; cdecl;
  TFuncType003 = function(conf: PCONF): TOpenSSL_C_INT; cdecl;
  TFuncType004 = function(conf: PCONF; bp: PBIO; eline: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TFuncType005 = function(conf: PCONF; bp: PBIO): TOpenSSL_C_INT; cdecl;
  TFuncType006 = function(conf: PCONF; c: ansichar): TOpenSSL_C_INT; cdecl;
  TFuncType007 = function(conf: PCONF; c: ansichar): TOpenSSL_C_INT; cdecl;
  TFuncType008 = function(conf: PCONF; name: PAnsiChar; eline: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  Tconf_method_st = record 
    name: PAnsiChar;
    create: TFuncType000;
    init: TFuncType001;
    destroy: TFuncType002;
    destroy_data: TFuncType003;
    load_bio: TFuncType004;
    dump: TFuncType005;
    is_number: TFuncType006;
    to_int: TFuncType007;
    load: TFuncType008;
  end;
  Tconf_st = record 
    meth: PCONF_METHOD;
    meth_data: pointer;
    data: Plhash_st_CONF_VALUE;
    flag_dollarid: TOpenSSL_C_INT;
    flag_abspath: TOpenSSL_C_INT;
    includedir: PAnsiChar;
    libctx: POSSL_LIB_CTX;
  end;
{$endif}

implementation

uses Sysutils
  {$ifdef OPENSSL_INTERNAL_NEED_THREADS}
   {$IFNDEF FPC}
     ,System.SyncObjs
     {$IFDEF POSIX}
       ,Posix.Pthread
     {$ELSE}
       ,Windows
     {$ENDIF}
   {$ELSE}
     ,SyncObjs
   {$ENDIF}
  {$endif}
  ,Classes, OpenSSLExceptionHandlers;

  {$if not declared(__FILE__)}
  const
    {$ifdef FPC}
    __FILE__ = {$include %FILE%};
    {$else}
    __FILE__ = '$(INPUTFILENAME)';
    {$endif}
  {$ifend}
  {$if not declared(__LINE__)}
  const
    __LINE__ = 0;
  {$ifend}
  {$if not declared(OPENSSL_FILE)}
  const
    OPENSSL_FILE = __FILE__;
  {$ifend}
  {$if not declared(OPENSSL_LINE)}
  const
    OPENSSL_LINE  = 0;
  {$ifend}

{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
end;

{$endif} {OPENSSL_STATIC_LINK_MODEL}

initialization

{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef EMPTY_LOAD_FUNCTION}
Register_SSLloader(@Load);
{$endif}
Register_SSLUnloader(@Unload);
{$endif}
{$if declared(LegacySupport_Initialization)}
LegacySupport_Initialization;
{$ifend}

finalization

{$if declared(LegacySupport_Finalization)}
LegacySupport_Finalization;
{$ifend}

end.



