unit IdSecRegisterSSL;

{$i IdCompilerDefines.inc}

interface

uses
  Classes , SysUtils, IdDsnCoreResourceStrings ,
  {$IFDEF FPC}
  LResources,
  {$ENDIF}
  IdSecOpenSSL;

procedure Register;

implementation

resourcestring

  RSSec = ' - Security';

{$IFNDEF FPC}
{$R IdSecRegisterOpenSSL.dcr}
{$ENDIF}

procedure Register;
begin
  {$IFDEF FPC}
  RegisterComponents(RSRegIndyIOHandlers+RSSec, [
  TIdSecServerIOHandlerSSLOpenSSL,
  TIdSecIOHandlerSocketOpenSSL
  ]);
  {$ELSE}
  RegisterComponents(RSRegIndyIOHandlers, [
  TIdSecServerIOHandlerSSLOpenSSL,
  TIdSecIOHandlerSocketOpenSSL
  ]);
  {$ENDIF}
end;

{$IFDEF FPC}
initialization
{$i IdSecRegisterSSL.lrs}
{$ENDIF}
end.

