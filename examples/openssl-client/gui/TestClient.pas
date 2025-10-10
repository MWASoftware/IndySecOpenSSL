unit TestClient;

{$IFDEF FPC}
{$MODE Delphi}
{$ENDIF}

interface

uses
  {$IFDEF FPC}
  Classes, {$IFDEF WINDOWS}Windows, {$ENDIF}Forms, Sysutils, StdCtrls,
  {$ELSE}
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,
  {$ENDIF}
  IdIOHandler, IdIOHandlerSocket,
  IdIOHandlerStack, IdSSL, IdSecOpenSSL, IdBaseComponent, IdComponent,
  IdTCPConnection, IdTCPClient, IdHTTP,  IdSecOpenSSLX509, IdSecOpenSSLAPI;

{$IFNDEF FPC}
const
  WM_DOTEST = WM_USER;
{$ENDIF}

const
  remoteSource = 'https://test.mwasoftware.co.uk/openssltest.txt';
  sGetException = 'Error: Status = %d returned when GETting %s';

  DefaultSSLDirs = '..' + DirectorySeparator + '..' + DirListDelimiter;

type
  TForm1 = class(TForm)
    IdHTTP1: TIdHTTP;
    IdSecIOHandlerSocketOpenSSL1: TIdSecIOHandlerSocketOpenSSL;
    Memo1: TMemo;
    Button1: TButton;
    procedure IdSecIOHandlerSocketOpenSSL1StatusInfo(const AMsg: string);
    function IdSecIOHandlerSocketOpenSSL1VerifyPeer(Certificate: TIdX509;
      AOk: Boolean; ADepth, AError: Integer): Boolean;
    procedure FormShow(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
  private
    { Private declarations }
    FClosing: boolean;
    procedure ShowCertificate(Certificate : TIdX509);
    {$IFDEF FPC}
    procedure OnDoTest(Data: PtrInt);
    {$ELSE}
    procedure OnDoTest(var Msg:TMessage); message WM_DOTEST;
    {$ENDIF}
    function CertificateType(Certificate: TIdX509): string;
    procedure GetResponse;
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

uses IdSecOpenSSLOptions;

{$IFDEF FPC}
{$R *.lfm}
{$ELSE}
{$R *.dfm}
{$ENDIF}

type
   TResponseTextBuffer = class(TMemoryStream)
    private
      function GetDataString: AnsiString;
    public
      property DataString: AnsiString read GetDataString;
    end;


procedure TForm1.Button1Click(Sender: TObject);
begin
  Close;
end;

function TForm1.CertificateType(Certificate: TIdX509): string;
begin
  if Certificate.Issuer.Hash.C1 = Certificate.Subject.Hash.C1 then
    Result := 'Root'
  else
    Result := 'Remote';
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
 FClosing := true;
 CanClose := true;
end;

procedure TForm1.FormShow(Sender: TObject);
begin
  Memo1.Lines.Clear;
  {$IFDEF FPC}
  Application.QueueAsyncCall(OnDoTest,0);
  {$ELSE}
  PostMessage(self.Handle,WM_DOTEST,0,0);
  {$ENDIF}
end;

procedure TForm1.GetResponse;
var ResponseStream: TResponseTextBuffer;
    SSLHandler: TIdSecIOHandlerSocketOpenSSL;
begin
    SSLHandler := IdHTTP1.IOHandler as TIdSecIOHandlerSocketOpenSSL;
    ResponseStream := TResponseTextBuffer.Create;
    try
      IdHTTP1.Get(remoteSource,ResponseStream);
      if assigned (SSLHandler.SSLSocket) then
        Memo1.Lines.Add('Using SSL/TLS Version ' + SSLHandler.SSLSocket.SSLProtocolVersionStr+ ' with cipher '+SSLHandler.SSLSocket.Cipher.Name);
      if IdHTTP1.ResponseCode = 200 then
      begin
        Memo1.Lines.Add('Remote Source returned:');
        Memo1.Lines.Add(ResponseStream.DataString);
      end
      else
        Memo1.Lines.Add(Format(sGetException,[IdHTTP1.ResponseCode,remoteSource]));
    finally
      ResponseStream.Free;
      SSLHandler.Close;
    end;
end;

procedure TForm1.IdSecIOHandlerSocketOpenSSL1StatusInfo(const AMsg: string);
begin
   If not FClosing then
     Memo1.Lines.Add('Status Info: '+AMsg);
end;

function TForm1.IdSecIOHandlerSocketOpenSSL1VerifyPeer(Certificate: TIdX509;
  AOk: Boolean; ADepth, AError: Integer): Boolean;
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('Client Side Verification');
  if AOK then
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification succeeded')
  else
   Memo1.Lines.Add(CertificateType(Certificate)+' Certificate verification failed');
  ShowCertificate(certificate);
  Result := AOK;
end;

{$IFDEF FPC}
procedure TForm1.OnDoTest(Data: PtrInt);
{$ELSE}
procedure TForm1.OnDoTest(var Msg: TMessage);
{$ENDIF}
begin
  if GetIOpenSSLDDL <> nil then
    GetIOpenSSLDDL.SetOpenSSLPath(DefaultSSLDirs);
  Memo1.Lines.Add('Using '+OpenSSLVersion);
  case GetIOpenSSL.GetLinkModel of
  lmDynamic:
    Memo1.Lines.Add('Link Model: Dynamic linking at run time');
  lmShared:
    Memo1.Lines.Add('Link Model: Static loading of a shared library');
  lmStatic:
    Memo1.Lines.Add('Link Model: Statically linked to a static library at link time');
  end;

  if GetIOpenSSLDDL <> nil then
    begin
      Memo1.Lines.Add('LibCrypto: '+GetIOpenSSLDDL.GetLibCryptoFilePath);
      Memo1.Lines.Add('LibSSL: '+GetIOpenSSLDDL.GetLibSSLFilePath);
    end;
  Memo1.Lines.Add('Working Directory = ' + GetCurrentDir);

  Memo1.Lines.Add('');
  Memo1.Lines.Add('Getting '+remoteSource+' with no verification');
  Memo1.Lines.Add('');

  GetResponse;

  {Repeat with verification}
   Memo1.Lines.Add('Getting '+remoteSource+' with verification');
   Memo1.Lines.Add('');

  (IdHTTP1.IOHandler as TIdSecIOHandlerSocketOpenSSL).SSLOptions.VerifyMode := [sslvrfPeer, sslvrfFailIfNoPeerCert];
  GetResponse;

end;

procedure TForm1.ShowCertificate(Certificate: TIdX509);
begin
  Memo1.Lines.Add('');
  Memo1.Lines.Add('X.509 Certificate Details');
  Memo1.Lines.Add('Subject: '+ Certificate.Subject.OneLine);
  Memo1.Lines.Add('Issuer: '+ Certificate.Issuer.OneLine);
  Memo1.Lines.Add('Not Before: '+DateTimeToStr(Certificate.notBefore));
  Memo1.Lines.Add('Not After: '+DateTimeToStr(Certificate.notAfter));
  Memo1.Lines.Add('');
end;

{ TResponseTextBuffer }

function TResponseTextBuffer.GetDataString: AnsiString;
begin
  SetLength(Result,Size);
  Position := 0;
  Read(Result[1],Size);
  SetCodePage(RawByteString(Result), DefaultSystemCodePage, False);
end;

end.
