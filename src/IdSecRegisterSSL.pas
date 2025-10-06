unit IdSecRegisterSSL;

{$i IdCompilerDefines.inc}

interface

uses
  Classes , SysUtils,
  {$IFDEF FPC}
  LResources,
  {$ENDIF}
  IdSecOpenSSL;

procedure Register;

implementation

resourcestring

  RSSec = 'IndySec';

{$IFNDEF FPC}
{$R IdSecRegisterOpenSSL.dcr}
{$ENDIF}

procedure Register;
begin
  {$IFDEF FPC}
  RegisterComponents(RSSec, [
  TIdSecServerIOHandlerSSLOpenSSL,
  TIdSecIOHandlerSocketOpenSSL
  ]);
  {$ELSE}
  RegisterComponents(RSSec, [
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

