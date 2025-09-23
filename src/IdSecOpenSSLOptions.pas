unit IdSecOpenSSLOptions;

{
  $Project$
  $Workfile$
  $Revision$
  $DateUTC$
  $Id$
  }
  {******************************************************************************}
  {                                                                              }
  {            Indy (Internet Direct) - Internet Protocols Simplified            }
  {                                                                              }
  {            https://www.indyproject.org/                                      }
  {            https://gitter.im/IndySockets/Indy                                }
  {                                                                              }
  {******************************************************************************}
  {                                                                              }
  {  This file is part of the Indy (Internet Direct) project, and is offered     }
  {  under the dual-licensing agreement described on the Indy website.           }
  {  (https://www.indyproject.org/license/)                                      }
  {                                                                              }
  {  Copyright:                                                                  }
  {   (c) 1993-2025, the Indy Pit Crew. All rights reserved.   }
  {                                                                              }
  {******************************************************************************}
  {                                                                              }
  {        Contributers:                                                         }
  {         Source code extracted from IdSecOpenSSL by Tony Whyman (MWA Software)}
  {         tony@mwasoftware.co.uk                                               }
  {                                                                              }
  {******************************************************************************}

{
  $Log$
}

interface

{$I IdCompilerDefines.inc}

{$IFNDEF USE_OPENSSL}
  {$message error Should not compile if USE_OPENSSL is not defined!!!}
{$ENDIF}

uses
  Classes,
  SysUtils
  ;

type
  TIdSecVersion = (sslUnknown,sslvSSLv2, sslvSSLv23, sslvSSLv3, sslvTLSv1,sslvTLSv1_1,
                    sslvTLSv1_2, sslvTLSv1_3);
                    {This list must be identical to TOpenSSL_Version as defined in IdOpenSSLHeaders_ssl}
  TIdSecVersions = set of TIdSecVersion;
  TIdSecMode = (sslmUnassigned, sslmClient, sslmServer, sslmBoth);
  TIdSecCtxMode = (sslCtxClient, sslCtxServer);
  TIdSecVerifyMode = (sslvrfPeer, sslvrfFailIfNoPeerCert, sslvrfClientOnce);
  TIdSecVerifyModeSet = set of TIdSecVerifyMode;

const
  DEF_SSLVERSION = sslvTLSv1_2;
  DEF_SSLVERSIONS = [sslvTLSv1_2,sslvTLSv1_3];
  MAX_SSLVERSION = sslvTLSv1_3;

type

  { TIdSecOptions }

  TIdSecOptions = class(TPersistent)
  private
    fUseSystemRootCertificateStore : boolean;
  protected
    fsRootCertFile,
    fsCertFile,
    fsKeyFile,
    fsDHParamsFile: String;
    fMethod: TIdSecVersion;
    fSSLVersions : TIdSecVersions;
    fMode: TIdSecMode;
    fVerifyDepth: Integer;
    fVerifyMode: TIdSecVerifyModeSet;
    //fVerifyFile,
    fVerifyDirs: String;
    fCipherList: String;
    procedure AssignTo(Destination: TPersistent); override;
    procedure SetSSLVersions(const AValue : TIdSecVersions);
    procedure SetMethod(const AValue : TIdSecVersion);
  public
    constructor Create;
    // procedure Assign(ASource: TPersistent); override;
  published
    property RootCertFile: String read fsRootCertFile write fsRootCertFile;
    property CertFile: String read fsCertFile write fsCertFile;
    property KeyFile: String read fsKeyFile write fsKeyFile;
    property DHParamsFile: String read fsDHParamsFile write fsDHParamsFile;
    property Method: TIdSecVersion read fMethod write SetMethod default DEF_SSLVERSION; {ignored with OpenSSL 1.1.0 or later}
    property SSLVersions : TIdSecVersions read fSSLVersions
                                          write SetSSLVersions
                                          default DEF_SSLVERSIONS;  {SSLVersions is only used to determine min version with OpenSSL 1.1.0 or later}
    property Mode: TIdSecMode read fMode write fMode;
    property VerifyMode: TIdSecVerifyModeSet read fVerifyMode write fVerifyMode;
    property VerifyDepth: Integer read fVerifyDepth write fVerifyDepth;
//    property VerifyFile: String read fVerifyFile write fVerifyFile;
    property VerifyDirs: String read fVerifyDirs write fVerifyDirs;
    property UseSystemRootCertificateStore: boolean read fUseSystemRootCertificateStore write fUseSystemRootCertificateStore default true;
    property CipherList: String read fCipherList write fCipherList;
  end;

implementation

uses
  IdSecOpenSSLHeaders_ssl
  ;

//////////////////////////////////////////////////////
//   TIdSecOptions
///////////////////////////////////////////////////////

constructor TIdSecOptions.Create;
begin
  inherited Create;
  fMethod := DEF_SSLVERSION;
  fSSLVersions := DEF_SSLVERSIONS;
  fUseSystemRootCertificateStore := true;
end;

procedure TIdSecOptions.SetMethod(const AValue: TIdSecVersion);
begin
  fMethod := AValue;
  if AValue = sslvSSLv23 then begin
    fSSLVersions := [sslvSSLv2,sslvSSLv3,sslvTLSv1,sslvTLSv1_1,sslvTLSv1_2];
  end else begin
    fSSLVersions := [AValue];
  end;
end;

procedure TIdSecOptions.SetSSLVersions(const AValue: TIdSecVersions);
begin
  fSSLVersions := AValue;
  if fSSLVersions = [sslvSSLv2] then begin
    fMethod := sslvSSLv2;
  end
  else if fSSLVersions = [sslvSSLv3] then begin
    fMethod := sslvSSLv3;
  end
  else if fSSLVersions = [sslvTLSv1] then begin
    fMethod := sslvTLSv1;
  end
  else if fSSLVersions = [sslvTLSv1_1 ] then begin
    fMethod := sslvTLSv1_1;
  end
  else if fSSLVersions = [sslvTLSv1_2 ] then begin
    fMethod := sslvTLSv1_2;
  end
  else if fSSLVersions = [sslvTLSv1_3 ] then begin
    if HasTLS_method  then
      fMethod := sslvTLSv1_3
    else
      fMethod := sslvTLSv1_2;
  end
  else begin
    fMethod := sslvSSLv23;
    if sslvSSLv23 in fSSLVersions then begin
      Exclude(fSSLVersions, sslvSSLv23);
      if fSSLVersions = [] then begin
        fSSLVersions := [sslvSSLv2,sslvSSLv3,sslvTLSv1,sslvTLSv1_1,sslvTLSv1_2];
      end;
    end;
  end;
end;

procedure TIdSecOptions.AssignTo(Destination: TPersistent);
var
  LDest: TIdSecOptions;
begin
  if Destination is TIdSecOptions then begin
    LDest := TIdSecOptions(Destination);
    LDest.RootCertFile := RootCertFile;
    LDest.CertFile := CertFile;
    LDest.KeyFile := KeyFile;
    LDest.DHParamsFile := DHParamsFile;
    LDest.Method := Method;
    LDest.SSLVersions := SSLVersions;
    LDest.Mode := Mode;
    LDest.VerifyMode := VerifyMode;
    LDest.VerifyDepth := VerifyDepth;
    LDest.fUseSystemRootCertificateStore := fUseSystemRootCertificateStore;
    LDest.VerifyDirs := VerifyDirs;
    LDest.CipherList := CipherList;
  end else begin
    inherited AssignTo(Destination);
  end;
end;


end.

